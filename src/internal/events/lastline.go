package events

import (
	"bytes"
	"io"
	"os"
)

// lastLine returns the last non-empty line of a log file and how many bytes
// it read to find it. It reads backwards from the end in chunks, so an append
// costs one line however long the month file has grown, rather than the
// whole file.
func lastLine(path string) ([]byte, int, error) {
	f, err := os.Open(path) //nolint:gosec // G304: impr's own log
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil {
		return nil, 0, err
	}
	const chunk = 4 << 10
	var tail []byte // the end of the file read so far
	read := 0
	for off := st.Size(); off > 0; {
		n := int64(chunk)
		if n > off {
			n = off
		}
		off -= n
		buf := make([]byte, n)
		if _, err := f.ReadAt(buf, off); err != nil && err != io.EOF {
			return nil, read, err
		}
		read += int(n)
		tail = append(buf, tail...)
		trimmed := bytes.TrimRight(tail, "\n")
		if i := bytes.LastIndexByte(trimmed, '\n'); i >= 0 {
			return trimmed[i+1:], read, nil
		}
		if off == 0 {
			return trimmed, read, nil
		}
	}
	return nil, read, nil
}
