package pgpmime_test

import (
	"bytes"
	"io"
	"log"
	"net/textproto"

	"github.com/emersion/go-message"
	"github.com/emersion/go-message/mail"
	"github.com/emersion/go-pgpmime"
	"golang.org/x/crypto/openpgp"
)

var to []*openpgp.Entity

func ExampleEncrypt() {
	var b bytes.Buffer

	// Create the mail header
	mh := mail.NewHeader()
	mh.SetAddressList("From", []*mail.Address{{"Mitsuha Miyamizu", "mitsuha.miyamizu@example.org"}})
	mh.SetSubject("Your Name")

	// Create the text part header
	th := mail.NewTextHeader()
	th.SetContentType("text/plain", nil)

	// Create a new PGP/MIME writer
	var ciphertext struct{*message.Writer}
	cleartext := pgpmime.Encrypt(&ciphertext, textproto.MIMEHeader(th.Header), to, nil, nil)

	// Add the PGP/MIME Content-Type header field to the mail header
	mh.Set("Content-Type", cleartext.ContentType())

	// Create a new mail writer with our mail header
	mw, err := message.CreateWriter(&b, mh.Header)
	if err != nil {
		log.Fatal(err)
	}
	// Set the PGP/MIME writer output to the mail body
	ciphertext.Writer = mw

	// Write the cleartext body
	_, err = io.WriteString(cleartext, "What's your name?")
	if err != nil {
		log.Fatal(err)
	}

	// Close all writers
	if err := cleartext.Close(); err != nil {
		log.Fatal(err)
	}
	if err := mw.Close(); err != nil {
		log.Fatal(err)
	}

	log.Println(b.String())
}

func ExampleSign() {
	var b bytes.Buffer

	e, err := openpgp.NewEntity("Mitsuha Miyamizu", "", "mitsuha.miyamizu@example.org", nil)
	if err != nil {
		log.Fatal(err)
	}

	mh := mail.NewHeader()
	mh.SetAddressList("From", []*mail.Address{{"Mitsuha Miyamizu", "mitsuha.miyamizu@example.org"}})
	mh.SetSubject("Your Name")

	bh := mail.NewTextHeader()
	bh.SetContentType("text/plain", nil)

	var signed struct{*message.Writer}
	body := pgpmime.Sign(&signed, textproto.MIMEHeader(bh.Header), e, nil)

	mh.Set("Content-Type", body.ContentType())

	mw, err := message.CreateWriter(&b, mh.Header)
	if err != nil {
		log.Fatal(err)
	}
	signed.Writer = mw

	_, err = io.WriteString(body, "What's your name?")
	if err != nil {
		log.Fatal(err)
	}

	if err := body.Close(); err != nil {
		log.Fatal(err)
	}
	if err := mw.Close(); err != nil {
		log.Fatal(err)
	}

	log.Println(b.String())
}
