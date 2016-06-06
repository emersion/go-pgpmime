package pgpmime

import (
	"errors"
	"io"

	"golang.org/x/crypto/openpgp/armor"
)

// Armored type for PGP encrypted messages.
const MessageType = "PGP MESSAGE"

// Encode a PGP message armor.
func EncodeArmoredMessage(w io.Writer) (io.WriteCloser, error) {
	return armor.Encode(w, MessageType, nil)
}

// Decode an armored PGP message.
func DecodeArmoredMessage(in io.Reader) (out io.Reader, err error) {
	block, err := armor.Decode(in)
	if err != nil {
		return
	}

	if block.Type != MessageType {
		err = errors.New("Not an armored PGP message")
		return
	}

	out = block.Body
	return
}
