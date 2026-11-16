package winres

import (
	"debug/pe"
	"encoding/binary"
	"unicode/utf16"
)

// ReadVersion reads the version strings (StringFileInfo) from a PE file's
// RT_VERSION resource: ProductName, FileVersion and the rest. A file with no
// version resource returns an empty map and no error.
func ReadVersion(path string) (map[string]string, error) {
	f, err := pe.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	sec := f.Section(".rsrc")
	if sec == nil {
		return map[string]string{}, nil
	}
	b, err := sec.Data()
	if err != nil {
		return nil, err
	}
	data, ok := findVersion(b, sec.VirtualAddress)
	if !ok {
		return map[string]string{}, nil
	}
	out := map[string]string{}
	walkVersion(data, out)
	return out, nil
}

// findVersion follows type 16, then the first id, then the first language,
// to the data entry, whose offset is an RVA.
func findVersion(b []byte, va uint32) ([]byte, bool) {
	u16 := func(o int) (int, bool) {
		if o < 0 || o+2 > len(b) {
			return 0, false
		}
		return int(binary.LittleEndian.Uint16(b[o:])), true
	}
	u32 := func(o int) (uint32, bool) {
		if o < 0 || o+4 > len(b) {
			return 0, false
		}
		return binary.LittleEndian.Uint32(b[o:]), true
	}
	// child returns the subdirectory or data-entry offset for an id (or the
	// first entry when id is 0) in the directory at o.
	child := func(o int, id uint32) (int, bool, bool) {
		named, ok1 := u16(o + 12)
		ids, ok2 := u16(o + 14)
		if !ok1 || !ok2 {
			return 0, false, false
		}
		for i := 0; i < named+ids; i++ {
			e := o + 16 + 8*i
			name, ok1 := u32(e)
			to, ok2 := u32(e + 4)
			if !ok1 || !ok2 {
				return 0, false, false
			}
			if id == 0 || (name&0x80000000 == 0 && name == id) {
				return int(to & 0x7fffffff), to&0x80000000 != 0, true
			}
		}
		return 0, false, false
	}
	o, sub, ok := child(0, rtVersion)
	if !ok || !sub {
		return nil, false
	}
	if o, sub, ok = child(o, 0); !ok || !sub {
		return nil, false
	}
	if o, sub, ok = child(o, 0); !ok || sub {
		return nil, false
	}
	rva, ok1 := u32(o)
	size, ok2 := u32(o + 4)
	if !ok1 || !ok2 || rva < va {
		return nil, false
	}
	start := int(rva - va)
	if start+int(size) > len(b) || start < 0 {
		return nil, false
	}
	return b[start : start+int(size)], true
}

func readUTF16Z(b []byte, o int) (string, int) {
	var u []uint16
	for o+2 <= len(b) {
		c := binary.LittleEndian.Uint16(b[o:])
		o += 2
		if c == 0 {
			break
		}
		u = append(u, c)
	}
	return string(utf16.Decode(u)), o
}

// walkVersion reads every String block under StringFileInfo into out.
func walkVersion(b []byte, out map[string]string) {
	var walk func(blk []byte, depth int, parent string)
	walk = func(blk []byte, depth int, parent string) {
		if len(blk) < 6 || depth > 4 {
			return
		}
		length := int(binary.LittleEndian.Uint16(blk))
		if length > len(blk) || length < 6 {
			return
		}
		blk = blk[:length]
		valueLen := int(binary.LittleEndian.Uint16(blk[2:]))
		typ := binary.LittleEndian.Uint16(blk[4:])
		key, o := readUTF16Z(blk, 6)
		o = (o + 3) &^ 3
		if parent == "table" && typ == 1 {
			v, _ := readUTF16Z(blk, o)
			_ = valueLen
			out[key] = v
			return
		}
		vsize := valueLen
		if typ == 1 {
			vsize *= 2
		}
		o = (o + vsize + 3) &^ 3
		next := "other"
		switch {
		case key == "StringFileInfo":
			next = "sfi"
		case parent == "sfi":
			next = "table"
		case key == "VS_VERSION_INFO":
			next = "root"
		}
		for o+6 <= len(blk) {
			n := int(binary.LittleEndian.Uint16(blk[o:]))
			if n < 6 || o+n > len(blk) {
				return
			}
			walk(blk[o:o+n], depth+1, next)
			o = (o + n + 3) &^ 3
		}
	}
	walk(b, 0, "")
}
