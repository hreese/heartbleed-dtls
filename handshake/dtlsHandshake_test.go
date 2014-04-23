package handshake

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"testing"
)

func TestHandshakeConstruction1(t *testing.T) {
	m := new(dtlsHandshake)

	// build dtlsHandshake struct
	m.handshakeType = HandshakeTypeClientHello
	m.messageSequence = 0x1234
	m.body = []byte{0xaa, 0xbb, 0xcc}

	// check if a handshake is equal to itself
	if !m.Equal(m) {
		t.Errorf("dtlsHandshake not equal() to itself")
	}

	// reference binary handshake
	m_bref := []byte{
		0x1,
		0x00, 0x00, 0x03,
		0x12, 0x34,
		0x00, 0x00, 0x00,
		0x00, 0x00, 0x03,
		0xaa, 0xbb, 0xcc,
	}

	buf := m.marshal()
	if !bytes.Equal(m_bref, buf) {
		t.Errorf("Error in dtlsHandshake.marshal()")
		fmt.Print("Reference:\n" + hex.Dump(m_bref))
		fmt.Print("Marshalled:\n" + hex.Dump(buf))
	}

	var u dtlsHandshake
	if u.unmarshal(buf) == false {
		t.Errorf("Unable to unmarshal buf")
		fmt.Println(hex.Dump(buf))
	}

	if !m.Equal(&u) {
		t.Errorf("m != m.Marshal().Unmarshal()")
		fmt.Printf("%#v\n", m)
		fmt.Printf("%#v\n", u)
	}
}

func TestHandshakeConstruction2(t *testing.T) {
	body := make([]byte, 52)
	_, err := rand.Read(body)
	if err != nil {
		t.Errorf("Unable to Read() from crypto/rand.")
	}

	m := dtlsHandshake{
		raw:             nil,
		handshakeType:   HandshakeTypeClientHello,
		length:          52 + 64,
		messageSequence: 0x0000,
		fragmentOffset:  64,
		fragmentLength:  52,
		body:            body,
	}

	ref := make([]byte, 12+52)
	ref_head := []byte{
		0x01,
		0x00, 0x00, 0x74,
		0x00, 0x00,
		0x00, 0x00, 0x40,
		0x00, 0x00, 0x34,
	}
	copy(ref[0:], ref_head)
	copy(ref[12:], body)

	buf := m.marshal()
	if !bytes.Equal(buf, ref) {
		t.Errorf("Error in dtlsHandshake.marshal()")
		fmt.Print("Reference:\n" + hex.Dump(ref))
		fmt.Print("Marshalled:\n" + hex.Dump(buf))
	}

	var u dtlsHandshake
	if u.unmarshal(buf) == false {
		t.Errorf("Unable to unmarshal buf")
		fmt.Println(hex.Dump(buf))
	}

	if !m.Equal(&u) {
		t.Errorf("m != m.Marshal().Unmarshal()")
		fmt.Printf("%+v\n", m)
		fmt.Printf("%+v\n", u)
	}
}
