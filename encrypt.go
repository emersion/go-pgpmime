package pgpmime

import (
	"io"
	"mime"
	"mime/multipart"
	"net/textproto"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
)

type encryptWriter struct {
	multipart *multipart.Writer
	armored io.WriteCloser
	cleartext io.WriteCloser

	h textproto.MIMEHeader
	to []*openpgp.Entity
	signed *openpgp.Entity
	config *packet.Config
}

func (ew *encryptWriter) open() error {
	// Create control information
	h := make(textproto.MIMEHeader)
	h.Add("Content-Type", "application/pgp-encrypted")
	w, err := ew.multipart.CreatePart(h)
	if err != nil {
		return err
	}
	if _, err := io.WriteString(w, "Version: 1\r\n"); err != nil {
		return err
	}

	// Create body part
	h = make(textproto.MIMEHeader)
	h.Add("Content-Type", "application/octet-stream")
	h.Add("Content-Disposition", "inline")
	w, err = ew.multipart.CreatePart(h)
	if err != nil {
		return err
	}

	// Create encrypted part
	ew.armored, err = armor.Encode(w, MessageType, nil)
	if err != nil {
		return err
	}
	ew.cleartext, err = openpgp.Encrypt(ew.armored, ew.to, ew.signed, nil, nil)
	if err != nil {
		return err
	}

	return writeMIMEHeader(ew.cleartext, ew.h)
}

func (ew *encryptWriter) Write(b []byte) (n int, err error) {
	// Make sure parts required at the begining of the message have been written
	if ew.cleartext == nil {
		if err := ew.open(); err != nil {
			return 0, err
		}
	}

	return ew.cleartext.Write(b)
}

func (ew *encryptWriter) Close() error {
	if ew.cleartext == nil {
		if err := ew.open(); err != nil {
			return err
		}
	}

	if err := ew.cleartext.Close(); err != nil {
		return err
	}
	if err := ew.armored.Close(); err != nil {
		return err
	}
	return ew.multipart.Close()
}

func (ew *encryptWriter) ContentType() string {
	return mime.FormatMediaType("multipart/encrypted", map[string]string{
		"boundary": ew.multipart.Boundary(),
		"protocol": "application/pgp-encrypted",
	})
}

// Encrypt creates a new encrypted PGP/MIME message writer.
func Encrypt(w io.Writer, h textproto.MIMEHeader, to []*openpgp.Entity, signed *openpgp.Entity, config *packet.Config) (cleartext Writer) {
	return &encryptWriter{
		multipart: multipart.NewWriter(w),

		h: h,
		to: to,
		signed: signed,
		config: config,
	}
}
