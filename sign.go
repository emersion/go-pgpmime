package pgpmime

import (
	"bytes"
	"io"
	"mime"
	"mime/multipart"
	"net/textproto"
	"crypto"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/packet"
)

func hashName(h crypto.Hash) string {
	switch h {
	case crypto.MD5:
		return "md5"
	case crypto.SHA1:
		return "sha1"
	case crypto.RIPEMD160:
		return "ripemd160"
	case crypto.SHA224:
		return "sha224"
	case crypto.SHA256:
		return "sha256"
	case crypto.SHA384:
		return "sha384"
	case crypto.SHA512:
		return "sha512"
	default:
		panic("pgpmime: unknown hash algorithm")
	}
}

type signWriter struct {
	multipart *multipart.Writer
	body io.WriteCloser
	signature <-chan io.Reader

	h textproto.MIMEHeader
	signer *openpgp.Entity
	config *packet.Config
}

func (sw *signWriter) open() error {
	w, err := sw.multipart.CreatePart(sw.h)
	if err != nil {
		return err
	}

	pr, pw := io.Pipe()
	ch := make(chan io.Reader, 1)
	sw.signature = ch
	go func() {
		var b bytes.Buffer
		err := openpgp.ArmoredDetachSign(&b, sw.signer, pr, sw.config)
		pr.CloseWithError(err)
		ch <- &b
	}()

	sw.body = struct{
		io.Writer
		io.Closer
	}{
		io.MultiWriter(w, pw),
		pw,
	}
	return nil
}

func (sw *signWriter) Write(b []byte) (n int, err error) {
	if sw.body == nil {
		if err := sw.open(); err != nil {
			return 0, err
		}
	}
	return sw.body.Write(b)
}

func (sw *signWriter) Close() error {
	if sw.body == nil {
		if err := sw.open(); err != nil {
			return err
		}
	}

	if err := sw.body.Close(); err != nil {
		return err
	}

	sig := <-sw.signature

	// Create signature part
	h := make(textproto.MIMEHeader)
	h.Add("Content-Type", "application/pgp-signature")
	w, err := sw.multipart.CreatePart(h)
	if err != nil {
		return err
	}
	if _, err := io.Copy(w, sig); err != nil {
		return err
	}

	return sw.multipart.Close()
}

func (sw *signWriter) ContentType() string {
	return mime.FormatMediaType("multipart/signed", map[string]string{
		"boundary": sw.multipart.Boundary(),
		"micalg": "pgp-" + hashName(sw.config.Hash()),
		"protocol": "application/pgp-signature",
	})
}

// Sign creates a new signed PGP/MIME message writer.
func Sign(w io.Writer, h textproto.MIMEHeader, signer *openpgp.Entity, config *packet.Config) (message Writer) {
	return &signWriter{
		multipart: multipart.NewWriter(w),

		h: h,
		signer: signer,
		config: config,
	}
}
