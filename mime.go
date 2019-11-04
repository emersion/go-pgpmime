package pgpmime

import (
	"bytes"
	"fmt"
	"io"
	"net/textproto"
	"sort"
)

// Borrowed from https://golang.org/src/mime/multipart/writer.go?s=2140:2215#L76
func writeMIMEHeader(w io.Writer, header textproto.MIMEHeader) error {
	var b bytes.Buffer
	keys := make([]string, 0, len(header))
	for k := range header {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		for _, v := range header[k] {
			fmt.Fprintf(&b, "%s: %s\r\n", k, v)
		}
	}
	_, err := io.Copy(w, &b)
	return err
}
