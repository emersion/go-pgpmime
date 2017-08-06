// pgpmime implements MIME security with OpenPGP, as defined in RFC 3156.
package pgpmime

import (
	"io"
)

// Writer writes a PGP/MIME message body.
type Writer interface {
	io.WriteCloser

	// ContentType returns the content type of the PGP/MIME message.
	ContentType() string
}
