// Package rules renders Windows allow rules for signed files (SIG-03,
// SD-099): an AppLocker publisher policy and a WDAC supplemental policy for
// exactly the files a request lists. There are no file-hash rules (Windows
// matches the Authenticode hash, which no build manifest records), no base
// WDAC policy (one allowing only this signer would block the operating
// system), and nothing random: the same request renders the same bytes.
package rules

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/sangehq/imprimatur/src/internal/contract"
)

// Collection is an AppLocker rule collection.
type Collection string

// Collections.
const (
	Exe    Collection = "Exe"
	Dll    Collection = "Dll"
	Msi    Collection = "Msi"
	Script Collection = "Script"
)

var byExt = map[string]Collection{
	".exe": Exe, ".com": Exe,
	".dll": Dll, ".ocx": Dll,
	".msi": Msi, ".msp": Msi, ".mst": Msi,
	".ps1": Script, ".bat": Script, ".cmd": Script, ".vbs": Script, ".js": Script,
}

// File is one signed file a rule covers.
type File struct {
	Path       string     `json:"path"`
	SHA256     string     `json:"sha256"`
	Collection Collection `json:"collection"`
	BinaryName string     `json:"binaryName"`
}

// Publisher is the signer, as Windows reads it from the certificate chain.
type Publisher struct {
	Subject    string `json:"subject"`
	LeafCN     string `json:"leafCn"`
	IssuerName string `json:"issuerName"`
	IssuerTBS  string `json:"issuerTbs"`
	EKU        string `json:"eku,omitempty"`
	Product    string `json:"product,omitempty"`
}

// Options shapes the policies.
type Options struct {
	Name           string            `json:"name"`
	Enforce        bool              `json:"enforce"`
	BasePolicyID   string            `json:"basePolicyId"`
	UserOrGroupSID string            `json:"userOrGroupSid,omitempty"`
	BinaryNames    map[string]string `json:"binaryNames,omitempty"`
	AppLocker      bool              `json:"appLocker"`
	WDAC           bool              `json:"wdac"`
}

// Request is what sange asks for (`impr rules --request <file>`).
type Request struct {
	Contract       int       `json:"contract"`
	ManifestDigest string    `json:"manifestDigest"`
	Commit         string    `json:"commit"`
	Version        string    `json:"version"`
	FileVersion    string    `json:"fileVersion"`
	Publisher      Publisher `json:"publisher"`
	Files          []File    `json:"files"`
	Options        Options   `json:"options"`
	PolicyID       string    `json:"policyId,omitempty"`
}

// Result is the answer.
type Result struct {
	Contract       int      `json:"contract"`
	Renderer       string   `json:"renderer"`
	ManifestDigest string   `json:"manifestDigest"`
	Files          []File   `json:"files"`
	AppLocker      string   `json:"appLocker,omitempty"`
	WDAC           string   `json:"wdac,omitempty"`
	Notes          []string `json:"notes,omitempty"`
}

var (
	digestRe = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	hexRe    = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)
	guidRe   = regexp.MustCompile(`^\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}$`)
	tbsRe    = regexp.MustCompile(`^([0-9A-Fa-f]{40}|[0-9A-Fa-f]{64}|[0-9A-Fa-f]{96}|[0-9A-Fa-f]{128})$`)
	oidRe    = regexp.MustCompile(`^[0-2](\.[0-9]+)+$`)
	sidRe    = regexp.MustCompile(`^S-1(-[0-9]+)+$`)
	verRe    = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$`)
)

// Render checks a request and renders its policies.
func Render(req Request, renderer string) (Result, error) {
	opt := req.Options
	if !opt.AppLocker && !opt.WDAC {
		opt.AppLocker, opt.WDAC = true, true
	}
	if opt.UserOrGroupSID == "" {
		opt.UserOrGroupSID = "S-1-1-0"
	}
	if opt.Name == "" {
		opt.Name = "imprimatur allow rules"
	}
	if err := check(req, opt); err != nil {
		return Result{}, err
	}
	files := append([]File(nil), req.Files...)
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	fv := req.FileVersion
	if fv == "" {
		fv = "0.0.0.0"
	}
	res := Result{Contract: contract.Version, Renderer: renderer, ManifestDigest: req.ManifestDigest, Files: files}
	level := "publisher"
	if req.Publisher.Product != "" {
		level = "file-publisher"
		res.Notes = append(res.Notes, "rules allow the listed binary names of product "+req.Publisher.Product+" at file version "+fv+" or newer")
	} else {
		res.Notes = append(res.Notes, "no product name: the rules allow anything this publisher signs")
	}
	res.Notes = append(res.Notes, "no file-hash rules; no base WDAC policy")
	if opt.AppLocker {
		res.AppLocker = string(renderAppLocker(req, opt, files, level, fv))
		if !opt.Enforce {
			res.Notes = append(res.Notes, "AppLocker collections are AuditOnly; enforcement is a separate, deliberate change")
		}
	}
	if opt.WDAC {
		w, err := renderWDAC(req, opt, files, level, fv)
		if err != nil {
			return Result{}, err
		}
		res.WDAC = string(w)
		res.Notes = append(res.Notes, "the WDAC supplemental policy takes audit or enforcement from its base policy")
	}
	return res, nil
}

func check(req Request, opt Options) error {
	var p []string
	if req.Contract != contract.Version {
		p = append(p, fmt.Sprintf("request contract %d; imprimatur speaks %d", req.Contract, contract.Version))
	}
	if !digestRe.MatchString(req.ManifestDigest) {
		p = append(p, "manifestDigest is not sha256:<hex>")
	}
	if len(req.Files) == 0 {
		p = append(p, "the request lists no files")
	}
	seen := map[string]bool{}
	for _, f := range req.Files {
		want, ok := byExt[strings.ToLower(path.Ext(f.Path))]
		switch {
		case !ok:
			p = append(p, f.Path+" is not a Windows executable, library, installer or script")
		case f.Collection != want:
			p = append(p, fmt.Sprintf("%s is in collection %s, not %s", f.Path, f.Collection, want))
		}
		if !hexRe.MatchString(f.SHA256) {
			p = append(p, f.Path+" has no sha256 digest")
		}
		if strings.TrimSpace(f.BinaryName) == "" || strings.ContainsAny(f.BinaryName, `/\`) {
			p = append(p, f.Path+" has no binary name")
		}
		if seen[f.Path] {
			p = append(p, f.Path+" is listed twice")
		}
		seen[f.Path] = true
	}
	if req.FileVersion != "" && !verRe.MatchString(req.FileVersion) {
		p = append(p, "fileVersion "+req.FileVersion+" is not four numbers")
	}
	if opt.AppLocker && strings.TrimSpace(req.Publisher.Subject) == "" {
		p = append(p, "AppLocker needs the publisher's certificate subject")
	}
	if opt.WDAC {
		if strings.TrimSpace(req.Publisher.LeafCN) == "" {
			p = append(p, "WDAC needs the leaf certificate's common name")
		}
		if !tbsRe.MatchString(req.Publisher.IssuerTBS) {
			p = append(p, "WDAC needs the issuing CA's TBS hash in hex")
		}
		if !guidRe.MatchString(opt.BasePolicyID) {
			p = append(p, "WDAC needs the base policy id as {GUID}; imprimatur renders supplemental policies only")
		}
	}
	if req.Publisher.EKU != "" && !oidRe.MatchString(req.Publisher.EKU) {
		p = append(p, "EKU "+req.Publisher.EKU+" is not a dotted OID")
	}
	if !sidRe.MatchString(opt.UserOrGroupSID) {
		p = append(p, "user or group "+opt.UserOrGroupSID+" is not a SID")
	}
	if len(p) > 0 {
		return contract.New(contract.Usage, "the allow-rules request cannot be rendered").WithDetails(p...)
	}
	return nil
}

// guid derives a stable, name-based GUID (version-5 layout over sha256).
func guid(parts ...string) string {
	h := sha256.Sum256([]byte("imprimatur\x00" + strings.Join(parts, "\x00")))
	b := h[:16]
	b[6] = (b[6] & 0x0f) | 0x50
	b[8] = (b[8] & 0x3f) | 0x80
	x := hex.EncodeToString(b)
	return x[0:8] + "-" + x[8:12] + "-" + x[12:16] + "-" + x[16:20] + "-" + x[20:32]
}

// EKUValue encodes a dotted OID as a WDAC EKU value: "01", the length, then
// the DER-encoded OID body, upper-case hex.
func EKUValue(oid string) (string, error) {
	if !oidRe.MatchString(oid) {
		return "", contract.New(contract.Usage, "EKU %s is not a dotted OID", oid)
	}
	arcs := strings.Split(oid, ".")
	nums := make([]uint64, len(arcs))
	for i, a := range arcs {
		n, err := strconv.ParseUint(a, 10, 64)
		if err != nil {
			return "", contract.New(contract.Usage, "EKU %s has an arc out of range", oid)
		}
		nums[i] = n
	}
	if nums[0] < 2 && nums[1] >= 40 {
		return "", contract.New(contract.Usage, "EKU %s has an invalid second arc", oid)
	}
	var body []byte
	body = base128(body, nums[0]*40+nums[1])
	for _, n := range nums[2:] {
		body = base128(body, n)
	}
	if len(body) > 127 {
		return "", contract.New(contract.Usage, "EKU %s is too long", oid)
	}
	return strings.ToUpper(hex.EncodeToString(append([]byte{0x01, byte(len(body))}, body...))), nil //nolint:gosec // G115: at most 127, checked above
}

func base128(b []byte, n uint64) []byte {
	var tmp [10]byte
	i := len(tmp) - 1
	tmp[i] = byte(n & 0x7f)
	for n >>= 7; n > 0; n >>= 7 {
		i--
		tmp[i] = byte(n&0x7f) | 0x80
	}
	return append(b, tmp[i:]...)
}

// ---- AppLocker ----------------------------------------------------------------

type alPolicy struct {
	XMLName     xml.Name       `xml:"AppLockerPolicy"`
	Version     string         `xml:"Version,attr"`
	Collections []alCollection `xml:"RuleCollection"`
}

type alCollection struct {
	Type            string   `xml:"Type,attr"`
	EnforcementMode string   `xml:"EnforcementMode,attr"`
	Rules           []alRule `xml:"FilePublisherRule"`
}

type alRule struct {
	ID          string `xml:"Id,attr"`
	Name        string `xml:"Name,attr"`
	Description string `xml:"Description,attr"`
	SID         string `xml:"UserOrGroupSid,attr"`
	Action      string `xml:"Action,attr"`
	Condition   alCond `xml:"Conditions>FilePublisherCondition"`
}

type alCond struct {
	PublisherName string  `xml:"PublisherName,attr"`
	ProductName   string  `xml:"ProductName,attr"`
	BinaryName    string  `xml:"BinaryName,attr"`
	Range         alRange `xml:"BinaryVersionRange"`
}

type alRange struct {
	Low  string `xml:"LowSection,attr"`
	High string `xml:"HighSection,attr"`
}

func binaryName(opt Options, f File) string {
	if n := opt.BinaryNames[f.Path]; n != "" {
		return n
	}
	return f.BinaryName
}

func renderAppLocker(req Request, opt Options, files []File, level, fv string) []byte {
	mode := "AuditOnly"
	if opt.Enforce {
		mode = "Enabled"
	}
	byColl := map[Collection][]File{}
	for _, f := range files {
		byColl[f.Collection] = append(byColl[f.Collection], f)
	}
	pub := req.Publisher
	desc := "imprimatur: signed release " + req.Version + ", build manifest " + req.ManifestDigest
	pol := alPolicy{Version: "1"}
	for _, c := range []Collection{Exe, Msi, Script, Dll} {
		fs := byColl[c]
		if len(fs) == 0 {
			continue
		}
		coll := alCollection{Type: string(c), EnforcementMode: mode}
		if level == "publisher" {
			coll.Rules = append(coll.Rules, alRule{ID: guid("applocker", string(c), pub.Subject, "*"),
				Name: "imprimatur: everything signed by " + pub.Subject, Description: desc, SID: opt.UserOrGroupSID, Action: "Allow",
				Condition: alCond{PublisherName: pub.Subject, ProductName: "*", BinaryName: "*", Range: alRange{Low: "*", High: "*"}}})
		} else {
			seen := map[string]bool{}
			for _, f := range fs {
				bin := strings.ToUpper(binaryName(opt, f))
				if seen[bin] {
					continue
				}
				seen[bin] = true
				coll.Rules = append(coll.Rules, alRule{ID: guid("applocker", string(c), pub.Subject, pub.Product, bin),
					Name:        fmt.Sprintf("imprimatur: %s (%s) %s and newer", bin, pub.Product, fv),
					Description: desc, SID: opt.UserOrGroupSID, Action: "Allow",
					Condition: alCond{PublisherName: pub.Subject, ProductName: strings.ToUpper(pub.Product), BinaryName: bin,
						Range: alRange{Low: fv, High: "*"}}})
			}
		}
		pol.Collections = append(pol.Collections, coll)
	}
	b, _ := xml.MarshalIndent(pol, "", "  ")
	return append([]byte(xml.Header), append(b, '\n')...)
}

// ---- WDAC ---------------------------------------------------------------------

const platformID = "{2E07F7E4-194C-4D20-B7C9-6F44A6C5A234}"

type siPolicy struct {
	XMLName      xml.Name      `xml:"urn:schemas-microsoft-com:sipolicy SiPolicy"`
	PolicyType   string        `xml:"PolicyType,attr"`
	VersionEx    string        `xml:"VersionEx"`
	PolicyID     string        `xml:"PolicyID"`
	BasePolicyID string        `xml:"BasePolicyID"`
	PlatformID   string        `xml:"PlatformID"`
	Rules        []siRule      `xml:"Rules>Rule"`
	EKUs         []siEKU       `xml:"EKUs>EKU"`
	FileRules    []siFileAttr  `xml:"FileRules>FileAttrib"`
	Signers      []siSigner    `xml:"Signers>Signer"`
	Scenarios    []siScenario  `xml:"SigningScenarios>SigningScenario"`
	UpdateSigner struct{}      `xml:"UpdatePolicySigners"`
	CiSigners    []siSignerRef `xml:"CiSigners>CiSigner"`
	Hvci         int           `xml:"HvciOptions"`
	Settings     []siSetting   `xml:"Settings>Setting"`
}

type siRule struct {
	Option string `xml:"Option"`
}

type siEKU struct {
	ID           string `xml:"ID,attr"`
	FriendlyName string `xml:"FriendlyName,attr"`
	Value        string `xml:"Value,attr"`
}

type siFileAttr struct {
	ID                 string `xml:"ID,attr"`
	FriendlyName       string `xml:"FriendlyName,attr"`
	FileName           string `xml:"FileName,attr"`
	MinimumFileVersion string `xml:"MinimumFileVersion,attr"`
}

type siSigner struct {
	ID            string     `xml:"ID,attr"`
	Name          string     `xml:"Name,attr"`
	CertRoot      siCertRoot `xml:"CertRoot"`
	CertEKU       *siRef     `xml:"CertEKU,omitempty"`
	CertPublisher siValue    `xml:"CertPublisher"`
	FileAttribs   []siRuleID `xml:"FileAttribRef"`
}

type siCertRoot struct {
	Type  string `xml:"Type,attr"`
	Value string `xml:"Value,attr"`
}

type siRef struct {
	ID string `xml:"ID,attr"`
}

type siValue struct {
	Value string `xml:"Value,attr"`
}

type siRuleID struct {
	RuleID string `xml:"RuleID,attr"`
}

type siSignerRef struct {
	SignerID string `xml:"SignerId,attr"`
}

type siScenario struct {
	Value        int           `xml:"Value,attr"`
	ID           string        `xml:"ID,attr"`
	FriendlyName string        `xml:"FriendlyName,attr"`
	Allowed      []siSignerRef `xml:"ProductSigners>AllowedSigners>AllowedSigner"`
}

type siSetting struct {
	Provider  string `xml:"Provider,attr"`
	Key       string `xml:"Key,attr"`
	ValueName string `xml:"ValueName,attr"`
	Value     string `xml:"Value>String"`
}

func renderWDAC(req Request, opt Options, files []File, level, fv string) ([]byte, error) {
	pub := req.Publisher
	base := strings.ToUpper(opt.BasePolicyID)
	policyID := req.PolicyID
	if !guidRe.MatchString(policyID) {
		policyID = "{" + strings.ToUpper(guid("wdac-policy", base, pub.Subject, pub.LeafCN, pub.Product, opt.Name)) + "}"
	}
	pol := siPolicy{PolicyType: "Supplemental Policy", VersionEx: fv, PolicyID: strings.ToUpper(policyID), BasePolicyID: base,
		PlatformID: platformID, Rules: []siRule{{Option: "Enabled:Unsigned System Integrity Policy"}}}
	name := pub.IssuerName
	if name == "" {
		name = pub.LeafCN
	}
	signer := siSigner{ID: "ID_SIGNER_IMPR_0", Name: name, CertRoot: siCertRoot{Type: "TBS", Value: strings.ToUpper(pub.IssuerTBS)},
		CertPublisher: siValue{Value: pub.LeafCN}}
	if pub.EKU != "" {
		v, err := EKUValue(pub.EKU)
		if err != nil {
			return nil, err
		}
		pol.EKUs = []siEKU{{ID: "ID_EKU_IMPR_0", FriendlyName: "signer EKU " + pub.EKU, Value: v}}
		signer.CertEKU = &siRef{ID: "ID_EKU_IMPR_0"}
	}
	if level == "file-publisher" {
		seen := map[string]bool{}
		for _, f := range files {
			bin := binaryName(opt, f)
			if seen[strings.ToLower(bin)] {
				continue
			}
			seen[strings.ToLower(bin)] = true
			id := fmt.Sprintf("ID_FILEATTRIB_IMPR_%d", len(pol.FileRules))
			pol.FileRules = append(pol.FileRules, siFileAttr{ID: id, FriendlyName: pub.Product + " " + bin, FileName: bin, MinimumFileVersion: fv})
			signer.FileAttribs = append(signer.FileAttribs, siRuleID{RuleID: id})
		}
	}
	pol.Signers = []siSigner{signer}
	pol.Scenarios = []siScenario{{Value: 12, ID: "ID_SIGNINGSCENARIO_IMPR_UMCI", FriendlyName: "user mode: " + opt.Name,
		Allowed: []siSignerRef{{SignerID: signer.ID}}}}
	pol.CiSigners = []siSignerRef{{SignerID: signer.ID}}
	pol.Settings = []siSetting{
		{Provider: "PolicyInfo", Key: "Information", ValueName: "Name", Value: opt.Name},
		{Provider: "PolicyInfo", Key: "Information", ValueName: "Id", Value: req.ManifestDigest},
	}
	b, err := xml.MarshalIndent(pol, "", "  ")
	if err != nil {
		return nil, contract.Wrap(contract.Unavailable, err, "render the WDAC policy")
	}
	return append([]byte(xml.Header), append(b, '\n')...), nil
}
