package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/hex"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/sangehq/imprimatur/src/internal/artifact"
	"github.com/sangehq/imprimatur/src/internal/backend"
	"github.com/sangehq/imprimatur/src/internal/contract"
	"github.com/sangehq/imprimatur/src/internal/rules"
	"github.com/sangehq/imprimatur/src/internal/winres"
)

var rulesFlags = flagSpec{"json": boolFlag, "strict": boolFlag, "request": stringFlag, "out-dir": stringFlag,
	"scope": stringFlag, "product": stringFlag, "file-version": stringFlag, "eku": stringFlag, "base-policy": stringFlag,
	"applocker": boolFlag, "wdac": boolFlag, "enforce": boolFlag, "name": stringFlag, "sid": stringFlag,
	"include-default-rules": boolFlag}

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
func rulesFromFiles(a *App, p parsed) (rules.Request, error) {
	scope := orDefault(p.str("scope"), "product")
	switch scope {
	case "publisher":
		if p.str("product") != "" {
			return rules.Request{}, contract.New(contract.Usage, "--scope publisher allows anything the publisher signs; drop --product, or use --scope product")
		}
	case "product", "file", "version":
		if scope == "version" && p.str("file-version") == "" {
			return rules.Request{}, contract.New(contract.Usage, "--scope version needs --file-version a.b.c.d")
		}
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
	for _, f := range p.pos {
		abs, err := filepath.Abs(f)
		if err != nil {
			return rules.Request{}, err
		}
		ext := strings.ToLower(filepath.Ext(abs))
		if ext != ".exe" && ext != ".dll" && ext != ".com" && ext != ".ocx" {
			return rules.Request{}, contract.New(contract.Usage, "%s: impr reads signatures from PE files (.exe, .dll); list other files in a --request", f)
		}
		s, err := backend.ReadPESigner(abs)
		if err != nil {
			return rules.Request{}, contract.Wrap(contract.Usage, err, "%s carries no Authenticode signature impr can read", f)
		}
		// A file changed after signing is never allow-listed (O-173).
		if err := backend.VerifyAuthenticode(abs); err != nil {
			return rules.Request{}, contract.Wrap(contract.VerifyFailed, err, "%s does not match its signature", f).
				WithFix("rebuild and re-sign it; never write rules for a file that fails this check")
		}
		if !s.Timestamped {
			a.say("rules     %s: its signature has no timestamp, so it stops being valid when the certificate expires; sign with a timestamp server", f)
		}
		// Rules pin the publisher's subject and its issuing CA, so files signed
		// by a renewed certificate of the same publisher and CA belong together.
		if signer == nil {
			signer = &s
		} else if s.Subject != signer.Subject || !bytes.Equal(s.Leaf.RawIssuer, signer.Leaf.RawIssuer) {
			return rules.Request{}, contract.New(contract.Usage, "%s is signed by %s, not %s like the other files; make one set of rules per publisher", f, s.Subject, signer.Subject)
		}
		if s.ProfileEKU != signer.ProfileEKU {
			return rules.Request{}, contract.New(contract.Usage, "%s is signed under Artifact Signing certificate profile EKU %q, not %q like the other files; make one set of rules per certificate profile",
				f, s.ProfileEKU, signer.ProfileEKU)
		}
		sum, err := artifact.SHA256(abs)
		if err != nil {
			return rules.Request{}, err
		}
		if readProduct {
			// The ProductName the file itself carries (impr build embeds it).
			v, err := winres.ReadVersion(abs)
			if err != nil {
				return rules.Request{}, contract.Wrap(contract.Usage, err, "%s: its version information cannot be read", f)
			}
			productOf[f] = v["ProductName"]
		}
		coll := rules.Exe
		if ext == ".dll" || ext == ".ocx" {
			coll = rules.Dll
		}
		files = append(files, rules.File{Path: filepath.ToSlash(f), SHA256: sum, Collection: coll, BinaryName: strings.ToUpper(filepath.Base(abs))})
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
		fv = p.str("file-version")
	}
	return rules.Request{Contract: contract.Version, ManifestDigest: "sha256:" + hex.EncodeToString(d[:]), FileVersion: fv, Scope: scope,
		Publisher: pub, Files: files, Options: opt}, nil
}
