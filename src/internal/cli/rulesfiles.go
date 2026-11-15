package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"sort"
	"strings"

	"github.com/sangehq/imprimatur/src/internal/artifact"
	"github.com/sangehq/imprimatur/src/internal/backend"
	"github.com/sangehq/imprimatur/src/internal/contract"
	"github.com/sangehq/imprimatur/src/internal/rules"
)

var rulesFlags = flagSpec{"json": boolFlag, "strict": boolFlag, "request": stringFlag, "out-dir": stringFlag,
	"scope": stringFlag, "product": stringFlag, "file-version": stringFlag, "eku": stringFlag, "base-policy": stringFlag,
	"applocker": boolFlag, "wdac": boolFlag, "enforce": boolFlag, "name": stringFlag, "sid": stringFlag}

// rulesFromFiles builds an allow-rules request from signed Windows files, the
// way the PowerShell toolkit read them: the publisher, leaf and issuing CA
// come from each file's own Authenticode signature, and every file must be
// signed by the same certificate. --scope picks how wide the rules are:
// publisher (anything that certificate signs), product (this product name),
// or version (this product at --file-version or newer). Hash rules (the old
// "file" scope) are not rendered.
func rulesFromFiles(a *App, p parsed) (rules.Request, error) {
	scope := orDefault(p.str("scope"), "product")
	switch scope {
	case "publisher":
		if p.str("product") != "" {
			return rules.Request{}, contract.New(contract.Usage, "--scope publisher allows anything the publisher signs; drop --product, or use --scope product")
		}
	case "product", "version":
		if p.str("product") == "" {
			return rules.Request{}, contract.New(contract.Usage, "--scope %s needs --product, the ProductName in the files' version information", scope)
		}
		if scope == "version" && p.str("file-version") == "" {
			return rules.Request{}, contract.New(contract.Usage, "--scope version needs --file-version a.b.c.d")
		}
	case "file":
		return rules.Request{}, contract.New(contract.Usage, "--scope file (hash rules) is not rendered: a hash rule breaks with every build; use product or version")
	default:
		return rules.Request{}, contract.New(contract.Usage, "--scope is publisher, product or version")
	}
	var files []rules.File
	var lines []string
	var signer *backend.PESigner
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
		// Rules pin the publisher's subject and its issuing CA, so files signed
		// by a renewed certificate of the same publisher and CA belong together.
		if signer == nil {
			signer = &s
		} else if s.Subject != signer.Subject || !bytes.Equal(s.Leaf.RawIssuer, signer.Leaf.RawIssuer) {
			return rules.Request{}, contract.New(contract.Usage, "%s is signed by %s, not %s like the other files; make one set of rules per publisher", f, s.Subject, signer.Subject)
		}
		sum, err := artifact.SHA256(abs)
		if err != nil {
			return rules.Request{}, err
		}
		coll := rules.Exe
		if ext == ".dll" || ext == ".ocx" {
			coll = rules.Dll
		}
		files = append(files, rules.File{Path: filepath.ToSlash(f), SHA256: sum, Collection: coll, BinaryName: strings.ToUpper(filepath.Base(abs))})
		lines = append(lines, sum+"  "+filepath.ToSlash(f))
	}
	sort.Strings(lines)
	d := sha256.Sum256([]byte(strings.Join(lines, "\n") + "\n"))
	pub := rules.Publisher{Subject: signer.Subject, LeafCN: signer.Leaf.Subject.CommonName, EKU: p.str("eku")}
	if scope != "publisher" {
		pub.Product = p.str("product")
	}
	if signer.Issuer != nil {
		tbs, err := backend.TBSHash(signer.Issuer)
		if err != nil {
			return rules.Request{}, contract.Wrap(contract.Usage, err, "the issuing CA cannot be pinned")
		}
		pub.IssuerName, pub.IssuerTBS = signer.Issuer.Subject.CommonName, tbs
	}
	opt := rules.Options{Name: p.str("name"), Enforce: p.on("enforce"), BasePolicyID: p.str("base-policy"),
		UserOrGroupSID: p.str("sid"), AppLocker: p.on("applocker"), WDAC: p.on("wdac")}
	if !opt.AppLocker && !opt.WDAC {
		opt.AppLocker, opt.WDAC = true, p.str("base-policy") != ""
		if !opt.WDAC {
			a.say("rules     no --base-policy: AppLocker rules only (a WDAC supplemental policy needs its base policy's {GUID})")
		}
	}
	if opt.WDAC && signer.Issuer == nil {
		return rules.Request{}, contract.New(contract.Usage, "the signature does not carry the issuing CA certificate, so WDAC rules cannot pin it; use --applocker")
	}
	fv := ""
	if scope == "version" {
		fv = p.str("file-version")
	}
	return rules.Request{Contract: contract.Version, ManifestDigest: "sha256:" + hex.EncodeToString(d[:]), FileVersion: fv,
		Publisher: pub, Files: files, Options: opt}, nil
}
