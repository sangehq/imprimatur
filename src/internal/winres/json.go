package winres

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// JSONFile is where go-winres keeps a project's resources, under the main
// package. impr reads its version strings and .ico icons.
const JSONFile = "winres/winres.json"

// FromJSON reads the version strings and icon from a go-winres winres.json:
// RT_VERSION's info block (the build's version still sets the versions) and
// the first RT_GROUP_ICON's first image list. Only .ico icons are taken; a
// PNG icon is refused, since converting images is go-winres's job, not impr's.
// It returns notes on what is not applied, such as manifest settings.
func FromJSON(path string, base Info) (Info, []byte, []string, error) {
	b, err := os.ReadFile(path) //nolint:gosec // G304: the project's own winres.json
	if err != nil {
		return base, nil, nil, err
	}
	var doc map[string]map[string]map[string]json.RawMessage
	if err := json.Unmarshal(b, &doc); err != nil {
		return base, nil, nil, fmt.Errorf("%s is not a go-winres file: %w", path, err)
	}
	var notes []string
	for k := range doc {
		if k != "RT_VERSION" && k != "RT_GROUP_ICON" && k != "RT_MANIFEST" {
			notes = append(notes, k+" is not applied")
		}
	}
	if _, ok := doc["RT_MANIFEST"]; ok {
		notes = append(notes, "RT_MANIFEST settings are not applied; impr embeds its CLI manifest (asInvoker, long paths)")
	}
	info := base
	for _, langs := range doc["RT_VERSION"] {
		for _, raw := range langs {
			var v struct {
				Info map[string]map[string]string `json:"info"`
			}
			if err := json.Unmarshal(raw, &v); err != nil {
				return base, nil, nil, fmt.Errorf("%s: RT_VERSION: %w", path, err)
			}
			keys := make([]string, 0, len(v.Info))
			for k := range v.Info {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			if len(keys) == 0 {
				continue
			}
			s := v.Info[keys[0]]
			set := func(dst *string, k string) {
				if x := strings.TrimSpace(s[k]); x != "" {
					*dst = x
				}
			}
			set(&info.ProductName, "ProductName")
			set(&info.FileDescription, "FileDescription")
			set(&info.CompanyName, "CompanyName")
			set(&info.LegalCopyright, "LegalCopyright")
			set(&info.OriginalFilename, "OriginalFilename")
			set(&info.InternalName, "InternalName")
		}
	}
	var ico []byte
	for _, langs := range doc["RT_GROUP_ICON"] {
		for _, raw := range langs {
			var files []string
			if err := json.Unmarshal(raw, &files); err != nil {
				var one string
				if json.Unmarshal(raw, &one) != nil {
					return base, nil, nil, fmt.Errorf("%s: RT_GROUP_ICON: an icon is a file name or a list of them", path)
				}
				files = []string{one}
			}
			if len(files) == 0 {
				continue
			}
			f := files[0]
			if !strings.EqualFold(filepath.Ext(f), ".ico") {
				return base, nil, nil, fmt.Errorf("%s: icon %s is not a .ico file; impr embeds .ico icons only (convert it, or pass --icon FILE.ico)", path, f)
			}
			if filepath.IsAbs(f) || strings.Contains(filepath.ToSlash(f), "..") {
				return base, nil, nil, fmt.Errorf("%s: icon %s must be inside the winres folder", path, f)
			}
			if ico, err = os.ReadFile(filepath.Join(filepath.Dir(path), f)); err != nil { //nolint:gosec // G304: checked to stay in the winres folder
				return base, nil, nil, err
			}
			if len(files) > 1 {
				notes = append(notes, "only the first icon file is embedded; put every size in one .ico")
			}
			break
		}
		break
	}
	sort.Strings(notes)
	return info, ico, notes, nil
}
