// Package winres writes Windows resources (version information, the
// application manifest, an icon) as a COFF object (.syso) the Go linker
// embeds, and reads version information back from a PE file. It replaces the
// PowerShell toolkit's go-winres step without running another program.
package winres

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
)

// Resource types.
const (
	rtIcon      = 3
	rtGroupIcon = 14
	rtVersion   = 16
	rtManifest  = 24
)

// langUS is the language every resource is stored under: en-US.
const langUS = 0x0409

// Info is the version information.
type Info struct {
	ProductName      string
	FileDescription  string
	CompanyName      string
	LegalCopyright   string
	OriginalFilename string
	InternalName     string
	ProductVersion   string // free text, e.g. v1.2.3-rc.1
	FileVersion      string // a.b.c.d, numbers only
}

var numericRe = regexp.MustCompile(`^\d+(\.\d+){0,3}`)

// FileVersion is the numeric a.b.c.d form of a version: v1.2.3-rc.1 becomes
// 1.2.3.0. Anything without leading numbers is 0.0.0.0.
func FileVersion(v string) string {
	n := numericRe.FindString(strings.TrimPrefix(v, "v"))
	parts := strings.Split(n, ".")
	for len(parts) < 4 {
		parts = append(parts, "0")
	}
	for i, p := range parts {
		if p == "" {
			parts[i] = "0"
		}
	}
	return strings.Join(parts[:4], ".")
}

func versionWords(v string) (ms, ls uint32, err error) {
	var n [4]uint32
	for i, p := range strings.Split(FileVersion(v), ".") {
		x, err := strconv.ParseUint(p, 10, 16)
		if err != nil {
			return 0, 0, fmt.Errorf("version part %q is not 0 to 65535", p)
		}
		n[i] = uint32(x)
	}
	return n[0]<<16 | n[1], n[2]<<16 | n[3], nil
}

// CLIManifest runs the program as the invoking user, declares support for
// Windows 7 to 11, and allows long paths.
const CLIManifest = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1">
    <application>
      <supportedOS Id="{35138b9a-5d96-4fbd-8e2d-a2440225f93a}"/>
      <supportedOS Id="{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}"/>
      <supportedOS Id="{1f676c76-80e1-4239-95bb-83d0f6d0da78}"/>
      <supportedOS Id="{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}"/>
    </application>
  </compatibility>
  <application xmlns="urn:schemas-microsoft-com:asm.v3">
    <windowsSettings>
      <longPathAware xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">true</longPathAware>
    </windowsSettings>
  </application>
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="asInvoker" uiAccess="false"/>
      </requestedPrivileges>
    </security>
  </trustInfo>
</assembly>
`

// ---- VS_VERSIONINFO -------------------------------------------------------------

func utf16z(s string) []byte {
	u := utf16.Encode([]rune(s + "\x00"))
	b := make([]byte, 2*len(u))
	for i, c := range u {
		binary.LittleEndian.PutUint16(b[2*i:], c)
	}
	return b
}

func pad4(b *bytes.Buffer) {
	for b.Len()%4 != 0 {
		b.WriteByte(0)
	}
}

// node is one version-info block: header, key, value, then children, each
// aligned to 32 bits from the start of the block.
func node(key string, typ uint16, value []byte, valueLen uint16, children ...[]byte) []byte {
	var b bytes.Buffer
	b.Write([]byte{0, 0}) // wLength, set below
	_ = binary.Write(&b, binary.LittleEndian, valueLen)
	_ = binary.Write(&b, binary.LittleEndian, typ)
	b.Write(utf16z(key))
	pad4(&b)
	b.Write(value)
	for _, c := range children {
		pad4(&b)
		b.Write(c)
	}
	out := b.Bytes()
	binary.LittleEndian.PutUint16(out, uint16(len(out))) //nolint:gosec // G115: a version block is far below 64 KiB
	return out
}

// VersionInfo builds the VS_VERSIONINFO resource.
func VersionInfo(in Info) ([]byte, error) {
	fms, fls, err := versionWords(in.FileVersion)
	if err != nil {
		return nil, err
	}
	pms, pls := fms, fls
	var fixed bytes.Buffer
	for _, v := range []uint32{0xFEEF04BD, 0x00010000, fms, fls, pms, pls, 0x3F, 0, 0x00040004, 1, 0, 0, 0} {
		_ = binary.Write(&fixed, binary.LittleEndian, v)
	}
	strs := map[string]string{"ProductName": in.ProductName, "FileDescription": in.FileDescription, "CompanyName": in.CompanyName,
		"LegalCopyright": in.LegalCopyright, "OriginalFilename": in.OriginalFilename, "InternalName": in.InternalName,
		"ProductVersion": in.ProductVersion, "FileVersion": FileVersion(in.FileVersion)}
	keys := make([]string, 0, len(strs))
	for k, v := range strs {
		if v != "" {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	var entries [][]byte
	for _, k := range keys {
		v := utf16z(strs[k])
		entries = append(entries, node(k, 1, v, uint16(len(v)/2))) //nolint:gosec // G115: one string, far below 64 KiB
	}
	table := node("040904b0", 1, nil, 0, entries...)
	sfi := node("StringFileInfo", 1, nil, 0, table)
	trans := []byte{0x09, 0x04, 0xb0, 0x04} // en-US, Unicode (1200)
	vfi := node("VarFileInfo", 1, nil, 0, node("Translation", 0, trans, 4))
	return node("VS_VERSION_INFO", 0, fixed.Bytes(), uint16(fixed.Len()), sfi, vfi), nil //nolint:gosec // G115: 52 bytes
}

// ---- icons ----------------------------------------------------------------------

type icoImage struct {
	entry [12]byte // width, height, colors, reserved, planes, bits per pixel, bytes
	data  []byte
}

// parseICO splits a .ico file into its images.
func parseICO(b []byte) ([]icoImage, error) {
	if len(b) < 6 || binary.LittleEndian.Uint16(b[0:]) != 0 || binary.LittleEndian.Uint16(b[2:]) != 1 {
		return nil, fmt.Errorf("not a .ico file")
	}
	n := int(binary.LittleEndian.Uint16(b[4:]))
	if n == 0 || len(b) < 6+16*n {
		return nil, fmt.Errorf("the .ico file holds no images or is cut short")
	}
	out := make([]icoImage, 0, n)
	for i := 0; i < n; i++ {
		e := b[6+16*i : 6+16*i+16]
		size := binary.LittleEndian.Uint32(e[8:])
		off := binary.LittleEndian.Uint32(e[12:])
		if uint64(off)+uint64(size) > uint64(len(b)) || size == 0 {
			return nil, fmt.Errorf("image %d of the .ico file is out of bounds", i+1)
		}
		var img icoImage
		copy(img.entry[:], e[:12])
		img.data = b[off : off+size]
		out = append(out, img)
	}
	return out, nil
}

// ---- the resource tree and the COFF object -----------------------------------

type resource struct {
	typ, id uint32
	data    []byte
}

// Arches are the GOARCH values a .syso can be written for, with their COFF
// machine and the relocation that makes a resource offset an RVA.
var arches = map[string]struct {
	machine uint16
	reloc   uint16
}{
	"amd64": {0x8664, 0x3}, // IMAGE_REL_AMD64_ADDR32NB
	"386":   {0x14c, 0x7},  // IMAGE_REL_I386_DIR32NB
	"arm64": {0xaa64, 0x2}, // IMAGE_REL_ARM64_ADDR32NB
}

// Supported reports whether a .syso can be written for goarch.
func Supported(goarch string) bool { _, ok := arches[goarch]; return ok }

// Syso builds the COFF object for goarch holding the version information, the
// manifest (empty for none) and the icon (a .ico file's bytes, empty for
// none).
func Syso(goarch string, in Info, manifest string, ico []byte) ([]byte, error) {
	a, ok := arches[goarch]
	if !ok {
		return nil, fmt.Errorf("no Windows resources for GOARCH %s (amd64, 386, arm64)", goarch)
	}
	vi, err := VersionInfo(in)
	if err != nil {
		return nil, err
	}
	res := []resource{{rtVersion, 1, vi}}
	if manifest != "" {
		res = append(res, resource{rtManifest, 1, []byte(manifest)})
	}
	if len(ico) > 0 {
		imgs, err := parseICO(ico)
		if err != nil {
			return nil, err
		}
		var grp bytes.Buffer
		_ = binary.Write(&grp, binary.LittleEndian, []uint16{0, 1, uint16(len(imgs))}) //nolint:gosec // G115: a .ico count is a uint16
		for i, img := range imgs {
			grp.Write(img.entry[:])
			_ = binary.Write(&grp, binary.LittleEndian, uint16(i+1))     //nolint:gosec // G115: as above
			res = append(res, resource{rtIcon, uint32(i + 1), img.data}) //nolint:gosec // G115: as above
		}
		res = append(res, resource{rtGroupIcon, 1, grp.Bytes()})
	}
	section, relocs := rsrc(res)
	return coff(a.machine, a.reloc, section, relocs), nil
}

// rsrc lays out the three-level resource directory (type, id, language), the
// data entries and the data, and returns the offsets of the data-entry fields
// the linker must relocate.
func rsrc(res []resource) ([]byte, []uint32) {
	sort.Slice(res, func(i, j int) bool {
		if res[i].typ != res[j].typ {
			return res[i].typ < res[j].typ
		}
		return res[i].id < res[j].id
	})
	var types []uint32
	byType := map[uint32][]resource{}
	for _, r := range res {
		if len(byType[r.typ]) == 0 {
			types = append(types, r.typ)
		}
		byType[r.typ] = append(byType[r.typ], r)
	}
	dirSize := func(n int) int { return 16 + 8*n }
	// Offsets: root, then one id directory per type, then one language
	// directory per resource, then data entries, then data.
	off := dirSize(len(types))
	idDir := map[uint32]int{}
	for _, t := range types {
		idDir[t] = off
		off += dirSize(len(byType[t]))
	}
	langDir := make([]int, len(res))
	for i := range res {
		langDir[i] = off
		off += dirSize(1)
	}
	entry := make([]int, len(res))
	for i := range res {
		entry[i] = off
		off += 16
	}
	dataOff := make([]int, len(res))
	for i, r := range res {
		off = (off + 7) &^ 7
		dataOff[i] = off
		off += len(r.data)
	}
	b := make([]byte, (off+7)&^7)
	dir := func(at, n int) {
		binary.LittleEndian.PutUint16(b[at+14:], uint16(n)) //nolint:gosec // G115: a handful of entries
	}
	put := func(at int, id uint32, target int, sub bool) {
		v := uint32(target) //nolint:gosec // G115: offsets inside a small section
		if sub {
			v |= 0x80000000
		}
		binary.LittleEndian.PutUint32(b[at:], id)
		binary.LittleEndian.PutUint32(b[at+4:], v)
	}
	dir(0, len(types))
	idx := 0
	for ti, t := range types {
		put(16+8*ti, t, idDir[t], true)
		dir(idDir[t], len(byType[t]))
		for ri, r := range byType[t] {
			put(idDir[t]+16+8*ri, r.id, langDir[idx], true)
			dir(langDir[idx], 1)
			put(langDir[idx]+16, langUS, entry[idx], false)
			binary.LittleEndian.PutUint32(b[entry[idx]:], uint32(dataOff[idx]))  //nolint:gosec // G115: as above
			binary.LittleEndian.PutUint32(b[entry[idx]+4:], uint32(len(r.data))) //nolint:gosec // G115: as above
			copy(b[dataOff[idx]:], r.data)
			idx++
		}
	}
	relocs := make([]uint32, len(res))
	for i := range res {
		relocs[i] = uint32(entry[i]) //nolint:gosec // G115: as above
	}
	return b, relocs
}

// coff wraps the section in an object file: one .rsrc section, its
// relocations, and the section symbol they refer to.
func coff(machine, relocType uint16, section []byte, relocs []uint32) []byte {
	const fileHeader, sectionHeader, relocSize = 20, 40, 10
	raw := fileHeader + sectionHeader
	relocAt := raw + len(section)
	symAt := relocAt + relocSize*len(relocs)
	var b bytes.Buffer
	w := func(v any) { _ = binary.Write(&b, binary.LittleEndian, v) }
	w(machine)
	w(uint16(1))     // sections
	w(uint32(0))     // time stamp: reproducible
	w(uint32(symAt)) //nolint:gosec // G115: a small object
	w(uint32(1))     // symbols
	w(uint16(0))     // optional header size
	w(uint16(0))     // characteristics
	b.WriteString(".rsrc\x00\x00\x00")
	w(uint32(0))            // virtual size
	w(uint32(0))            // virtual address
	w(uint32(len(section))) //nolint:gosec // G115: as above
	w(uint32(raw))          //nolint:gosec // G115: as above
	w(uint32(relocAt))      //nolint:gosec // G115: as above
	w(uint32(0))            // line numbers
	w(uint16(len(relocs)))  //nolint:gosec // G115: as above
	w(uint16(0))            // line numbers
	w(uint32(0x40000040))   // initialised data, readable
	b.Write(section)
	for _, r := range relocs {
		w(r)
		w(uint32(0)) // symbol 0: .rsrc
		w(relocType)
	}
	b.WriteString(".rsrc\x00\x00\x00")
	w(uint32(0)) // value
	w(int16(1))  // section 1
	w(uint16(0)) // type
	w(uint8(3))  // IMAGE_SYM_CLASS_STATIC
	w(uint8(0))  // no aux symbols
	w(uint32(4)) // empty string table
	return b.Bytes()
}
