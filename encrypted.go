// Implements MIME security with OpenPGP, as defined in RFC 3156.
package pgpmime

import (
	"io"
	"mime/multipart"
	"net/textproto"

	"golang.org/x/crypto/openpgp"
)

// A PGP/MIME encrypter.
type Encrypter struct {
	multipart *multipart.Writer
	armored io.WriteCloser
	encrypted io.WriteCloser

	to []*openpgp.Entity
	signed *openpgp.Entity

	opened bool
}

// Write control information and create encrypted part.
func (ew *Encrypter) open() (err error) {
	// Create control information
	h := make(textproto.MIMEHeader)
	h.Add("Content-Type", "application/pgp-encrypted")
	hw, err := ew.multipart.CreatePart(h)
	if err != nil {
		return
	}
	if _, err = io.WriteString(hw, "Version: 1\r\n"); err != nil {
		return
	}

	// Create body part
	h = make(textproto.MIMEHeader)
	h.Add("Content-Type", "application/octet-stream")
	h.Add("Content-Disposition", "inline")
	bw, err := ew.multipart.CreatePart(h)
	if err != nil {
		return
	}

	// Create encrypted part
	if ew.armored, err = EncodeArmoredMessage(bw); err != nil {
		return
	}
	if ew.encrypted, err = openpgp.Encrypt(ew.armored, ew.to, ew.signed, nil, nil); err != nil {
		return
	}

	return
}

// Write encrypted data.
func (ew *Encrypter) Write(b []byte) (n int, err error) {
	// Make sure parts required at the begining of the message have been written
	if !ew.opened {
		if err = ew.open(); err != nil {
			return
		}
		ew.opened = true
	}

	return ew.encrypted.Write(b)
}

// Finish the PGP/MIME message.
func (ew *Encrypter) Close() (err error) {
	if !ew.opened {
		if err = ew.open(); err != nil {
			return
		}
		ew.opened = true
	}

	if err = ew.encrypted.Close(); err != nil {
		return
	}
	if err = ew.armored.Close(); err != nil {
		return
	}
	err = ew.multipart.Close()
	return
}

// Get the Content-Type of this PGP/MIME message.
func (ew *Encrypter) ContentType() string {
	return "multipart/encrypted; boundary=" + ew.multipart.Boundary() + "; protocol=\"application/pgp-encrypted\""
}

// Create a new PGP/MIME encrypter.
func NewEncrypter(w io.Writer, to []*openpgp.Entity, signed *openpgp.Entity) *Encrypter {
	return &Encrypter{
		multipart: multipart.NewWriter(w),

		to: to,
		signed: signed,
	}
}
