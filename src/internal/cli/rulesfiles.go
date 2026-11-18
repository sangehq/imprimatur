package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/sangehq/imprimatur/src/internal/artifact"
	"github.com/sangehq/imprimatur/src/internal/backend"
	"github.com/sangehq/imprimatur/src/internal/contract"
	"github.com/sangehq/imprimatur/src/internal/profile"
	"github.com/sangehq/imprimatur/src/internal/rules"
	"github.com/sangehq/imprimatur/src/internal/signing"
	"github.com/sangehq/imprimatur/src/internal/winres"
)

var rulesFlags = flagSpec{"json": boolFlag, "strict": boolFlag, "request": stringFlag, "out-dir": stringFlag,
	"scope": stringFlag, "product": stringFlag, "file-version": stringFlag, "eku": stringFlag, "base-policy": stringFlag,
	"applocker": boolFlag, "wdac": boolFlag, "enforce": boolFlag, "name": stringFlag, "sid": stringFlag, "manifest": stringFlag,
	"include-default-rules": boolFlag, "profile": stringFlag, "without-signed-record": boolFlag}

// ruleEKU is the EKU a WDAC rule pins (O-181). For an Artifact Signing
// certificate it is the certificate profile's own EKU, read from the file
// when --eku is not given; the generic Artifact Signing EKU matches every
// customer under the CA, so it is refused, as is an EKU the file lacks.
func ruleEKU(a *App, given string, s *backend.PESigner) (string, error) {
	if given == backend.ArtifactSigningEKU {
		return "", contract.New(contract.Usage, "--eku %s is the generic Artifact Signing EKU: a rule pinned to it allows every Artifact Signing customer under the same CA", given).
			WithFix(orDefault(s.ProfileEKU, "the certificate profile's own EKU (1.3.6.1.4.1.311.97.…)"))
	}
	if given != "" {
		if !slices.ContainsFunc(s.Leaf.UnknownExtKeyUsage, func(o asn1.ObjectIdentifier) bool { return o.String() == given }) {
			return "", contract.New(contract.Usage, "the signing certificate does not carry EKU %s, so no file would match", given)
		}
		return given, nil
	}
	if s.ProfileEKU != "" {
		a.say("rules     EKU %s, the Artifact Signing certificate profile's, read from the signature", s.ProfileEKU)
	} else if s.ArtifactSigning {
		a.say("rules     an Artifact Signing certificate with no profile EKU; the rules pin the CA and the publisher only")
	}
	return s.ProfileEKU, nil
}

// rulesFromFiles builds an allow-rules request from signed Windows files, the
// way the PowerShell toolkit read them: the publisher, leaf and issuing CA
// come from each file's own Authenticode signature, and every file must be
// signed by the same certificate. --scope picks how wide the rules are, with
// the PowerShell meanings (ID-11): publisher (anything that certificate
// signs), product (any file of this product), file (this product and file
// name, any version) or version (and --file-version or newer).
func rulesFromFiles(a *App, p parsed, want map[string]string) (rules.Request, error) {
	pin, err := rulesPin(a, p.str("profile"))
	if err != nil {
		return rules.Request{}, err
	}
	scope := orDefault(p.str("scope"), "product")
	switch scope {
	case "publisher":
		if p.str("product") != "" {
			return rules.Request{}, contract.New(contract.Usage, "--scope publisher allows anything the publisher signs; drop --product, or use --scope product")
		}
	case "product", "file", "version":
		if scope != "version" && p.str("file-version") != "" {
			return rules.Request{}, contract.New(contract.Usage, "--scope %s allows any version; use --scope version with --file-version", scope)
		}
	default:
		return rules.Request{}, contract.New(contract.Usage, "--scope is publisher, product, file or version")
	}
	var files []rules.File
	var lines []string
	var signer *backend.PESigner
	product := p.str("product")
	readProduct := product == "" && scope != "publisher"
	productOf := map[string]string{}
	versionOf := map[string]string{}
	for _, f := range p.pos {
		abs, err := filepath.Abs(f)
		if err != nil {
			return rules.Request{}, err
		}
		ext := strings.ToLower(filepath.Ext(abs))
		if ext != ".exe" && ext != ".dll" && ext != ".com" && ext != ".ocx" {
			return rules.Request{}, contract.New(contract.Usage, "%s: impr reads signatures from PE files (.exe, .dll); list other files in a --request", f)
		}
		// One read: the signer, the signature check, the digest and the
		// version information all come from these bytes (security review, I-15).
		data, err := os.ReadFile(abs) //nolint:gosec // G304: a signed file the operator named
		if err != nil {
			return rules.Request{}, contract.Wrap(contract.Usage, err, "read %s", f)
		}
		s, err := backend.ReadPESignerBytes(data)
		if err != nil {
			return rules.Request{}, contract.Wrap(contract.Usage, err, "%s carries no Authenticode signature impr can read", f)
		}
		// A file changed after signing is never allow-listed (O-173).
		if err := backend.VerifyAuthenticodeBytes(data); err != nil {
			return rules.Request{}, contract.Wrap(contract.VerifyFailed, err, "%s does not match its signature", f).
				WithFix("rebuild and re-sign it; never write rules for a file that fails this check")
		}
		// The signer is the profile's (security review R6): rules for a file
		// signed by anyone else's certificate are never written.
		if pin != nil {
			if why := windowsPinMismatch(s, pin); why != "" {
				return rules.Request{}, contract.New(contract.VerifyFailed, "%s %s; no rules were written", f, why).
					WithFix("impr verify " + f + " --profile " + p.str("profile"))
			}
		}
		if !s.Timestamped {
			a.say("rules     %s: its signature has no timestamp, so it stops being valid when the certificate expires; sign with a timestamp server", f)
		}
		// Rules pin the publisher's subject and the certificate below the root,
		// so files signed by renewed certificates under the same PCA belong
		// together.
		if signer == nil {
			signer = &s
		} else if s.Subject != signer.Subject || !bytes.Equal(s.PCA.Raw, signer.PCA.Raw) {
			// One publisher to WDAC is one subject under one pinned PCA; the
			// issuing CAs below it may differ (Artifact Signing rotates them).
			return rules.Request{}, contract.New(contract.Usage, "%s is signed by %s under %s, not %s under %s like the other files; make one set of rules per publisher",
				f, s.Subject, s.PCA.Subject.CommonName, signer.Subject, signer.PCA.Subject.CommonName)
		}
		if s.ProfileEKU != signer.ProfileEKU {
			return rules.Request{}, contract.New(contract.Usage, "%s is signed under Artifact Signing certificate profile EKU %q, not %q like the other files; make one set of rules per certificate profile",
				f, s.ProfileEKU, signer.ProfileEKU)
		}
		digest := sha256.Sum256(data)
		sum := hex.EncodeToString(digest[:])
		if w, ok := want[abs]; ok && !strings.EqualFold(w, sum) {
			return rules.Request{}, contract.New(contract.VerifyFailed, "%s is not the file the signed record lists; no rules were written", f).
				WithDetails("signed record "+strings.ToLower(w), "on disk       "+sum)
		}
		// The version information the file carries (impr build embeds it):
		// its ProductName, OriginalFilename and FileVersion.
		v, verr := winres.ReadVersionBytes(data)
		if readProduct {
			if verr != nil {
				return rules.Request{}, contract.Wrap(contract.Usage, verr, "%s: its version information cannot be read", f)
			}
			productOf[f] = v["ProductName"]
		}
		versionOf[f] = v["FileVersion"]
		bin := strings.ToUpper(filepath.Base(abs))
		if o := strings.TrimSpace(v["OriginalFilename"]); o != "" {
			// The name the file was built as: the amd64 and arm64 builds of one
			// program share it, so they make one rule (O-175).
			bin = strings.ToUpper(o)
		}
		coll := rules.Exe
		if ext == ".dll" || ext == ".ocx" {
			coll = rules.Dll
		}
		files = append(files, rules.File{Path: filepath.ToSlash(f), SHA256: sum, Collection: coll, BinaryName: bin})
		lines = append(lines, sum+"  "+filepath.ToSlash(f))
	}
	if readProduct {
		for f, pr := range productOf {
			switch {
			case pr == "":
				return rules.Request{}, contract.New(contract.Usage, "--scope %s needs --product: %s carries no ProductName in its version information", scope, f).
					WithFix("impr rules ... --product \"Product Name\"", "build it with impr build, which embeds the product name")
			case product == "":
				product = pr
			case pr != product:
				return rules.Request{}, contract.New(contract.Usage, "the files name different products (%q and %q); make one set of rules per product, or pass --product", product, pr)
			}
		}
		a.say("rules     product %q, read from the files' version information", product)
	}
	sort.Strings(lines)
	d := sha256.Sum256([]byte(strings.Join(lines, "\n") + "\n"))
	eku, err := ruleEKU(a, p.str("eku"), signer)
	if err != nil {
		return rules.Request{}, err
	}
	pub := rules.Publisher{Subject: backend.AppLockerPublisher(signer.Leaf.RawSubject), LeafCN: signer.Leaf.Subject.CommonName, EKU: eku}
	if scope != "publisher" {
		pub.Product = product
	}
	// WDAC pins the certificate below the root (O-180). A leaf that is not
	// self-signed and carries no issuer gives nothing to pin.
	pinnable := len(signer.Chain) > 1 || bytes.Equal(signer.Leaf.RawSubject, signer.Leaf.RawIssuer)
	if pinnable {
		tbs, err := backend.TBSHash(signer.PCA)
		if err != nil {
			return rules.Request{}, contract.Wrap(contract.Usage, err, "the certificate below the root cannot be pinned")
		}
		pub.IssuerName, pub.IssuerTBS = signer.PCA.Subject.CommonName, tbs
	}
	opt := rules.Options{Name: p.str("name"), Enforce: p.on("enforce"), BasePolicyID: p.str("base-policy"),
		UserOrGroupSID: p.str("sid"), AppLocker: p.on("applocker"), WDAC: p.on("wdac"), IncludeDefaultRules: p.on("include-default-rules")}
	if !opt.AppLocker && !opt.WDAC {
		opt.AppLocker, opt.WDAC = true, p.str("base-policy") != ""
		if !opt.WDAC {
			a.say("rules     no --base-policy: AppLocker rules only (a WDAC supplemental policy needs its base policy's {GUID})")
		}
	}
	if opt.WDAC && !pinnable {
		return rules.Request{}, contract.New(contract.Usage, "the signature does not carry the issuing CA certificate, so WDAC rules cannot pin it; use --applocker")
	}
	fv := ""
	if scope == "version" {
		if fv = p.str("file-version"); fv == "" {
			// The lowest version among the files (O-175), as the PowerShell
			// rules allowed each group from its minimum version on.
			for f, v := range versionOf {
				if v == "" {
					return rules.Request{}, contract.New(contract.Usage, "--scope version needs --file-version: %s carries no FileVersion", f)
				}
				if fv == "" || slices.Compare(fourPart(v), fourPart(fv)) < 0 {
					fv = v
				}
			}
			a.say("rules     minimum file version %s, read from the files", fv)
		}
	}
	if opt.Name == "" && scope != "publisher" {
		opt.Name = product // O-185: the rules are named after the product
	}
	return rules.Request{Contract: contract.Version, ManifestDigest: "sha256:" + hex.EncodeToString(d[:]), FileVersion: fv, Scope: scope,
		Publisher: pub, Files: files, Options: opt}, nil
}

// fourPart is a FileVersion as numbers, for ordering.
func fourPart(v string) []int {
	var out []int
	for _, x := range strings.Split(v, ".") {
		n, _ := strconv.Atoi(strings.TrimSpace(x))
		out = append(out, n)
	}
	return out
}

// windowsFilesOf lists the Windows binaries of a build manifest, as paths
// under the build's root (ID-20). Each path must resolve inside the root. When
// the signed record impr sign wrote sits beside it, the record must belong to
// this build, and the digests it holds come back, so a file swapped after
// signing is refused (security review R6); the record's profile is the
// default --profile. Without a record nothing ties the files to a signing run,
// so it is refused unless the caller opts out (owner decision D-S3, ID-30);
// --strict refuses even then.
func windowsFilesOf(a *App, manifest string, optOut, strict bool) ([]string, map[string]string, string, error) {
	bm, err := artifact.ReadManifest(manifest)
	if err != nil {
		return nil, nil, "", contract.Wrap(contract.Usage, err, "read the build manifest %s", manifest)
	}
	root := filepath.Dir(filepath.Dir(bm.Path)) // <root>/build/build-manifest.json
	var files []string
	for _, a := range bm.Artifacts {
		ext := strings.ToLower(filepath.Ext(a.Path))
		if ext == ".exe" || ext == ".dll" {
			path, err := artifact.Resolve(root, a.Path)
			if err != nil {
				return nil, nil, "", contract.Wrap(contract.VerifyFailed, err, "the build manifest %s", manifest)
			}
			files = append(files, path)
		}
	}
	if len(files) == 0 {
		return nil, nil, "", contract.New(contract.Usage, "%s lists no Windows binaries", manifest)
	}
	rec := filepath.Join(bm.Dir, signing.ManifestFile)
	raw, err := os.ReadFile(rec) //nolint:gosec // G304: the signed record beside the build manifest
	if err != nil {
		if !optOut || strict {
			return nil, nil, "", contract.New(contract.VerifyFailed, "no signed record (%s) beside %s, so nothing ties these files to a signing run; no rules were written", signing.ManifestFile, manifest).
				WithFix("impr sign, then impr rules", "name the files and --profile instead", "impr rules --without-signed-record (not with --strict)")
		}
		a.say("rules     --without-signed-record: the files' digests and signer are not checked against a signing run")
		return files, nil, "", nil
	}
	var m signing.Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, nil, "", contract.Wrap(contract.VerifyFailed, err, "read the signed record %s", rec)
	}
	if m.BuildManifestDigest != bm.Digest {
		return nil, nil, "", contract.New(contract.VerifyFailed, "the signed record %s belongs to another build manifest", rec).
			WithDetails("record "+m.BuildManifestDigest, "build  "+bm.Digest)
	}
	want := map[string]string{}
	for _, sa := range m.Artifacts {
		path, err := artifact.Resolve(root, sa.Path)
		if err != nil {
			return nil, nil, "", contract.Wrap(contract.VerifyFailed, err, "the signed record %s", rec)
		}
		want[path] = sa.OutputSHA256
	}
	for _, f := range files {
		if _, ok := want[f]; !ok {
			return nil, nil, "", contract.New(contract.VerifyFailed, "%s is in the build manifest but was not signed (%s)", artifact.RelToRoot(root, f), rec)
		}
	}
	return files, want, m.Profile, nil
}

// rulesPin loads the profile whose Windows certificate the files must carry.
func rulesPin(a *App, name string) (*profile.WindowsSpec, error) {
	if name == "" {
		return nil, nil
	}
	st, err := a.store()
	if err != nil {
		return nil, err
	}
	pr, ok, err := st.Get(name)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, profile.ErrMissing(name)
	}
	if pr.Platforms.Windows == nil {
		return nil, contract.New(contract.Usage, "signing profile %s has no windows configuration", name)
	}
	return pr.Platforms.Windows, nil
}

// windowsPinMismatch says why s is not one of w's pinned certificates, or "".
// A certificate matches when every field the signer pins agrees.
func windowsPinMismatch(s backend.PESigner, w *profile.WindowsSpec) string {
	type pinned struct{ thumb, subject string }
	pins := []pinned{{w.Thumbprint, w.Subject}}
	if len(w.Signers) > 0 {
		pins = nil
		for _, x := range w.Signers {
			pins = append(pins, pinned{x.Thumbprint, x.Subject})
		}
	}
	for _, pn := range pins {
		if pn.thumb == "" && pn.subject == "" {
			continue
		}
		if pn.thumb != "" && !strings.EqualFold(pn.thumb, s.Thumbprint) {
			continue
		}
		if pn.subject != "" && !backend.SubjectsEqual(s.Subject, pn.subject) && !backend.SubjectsEqual(s.SubjectRFC, pn.subject) {
			continue
		}
		return ""
	}
	return "is signed by " + s.Subject + " (" + s.Thumbprint + "), not a certificate the profile pins"
}
