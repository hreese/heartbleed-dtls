package heartbleed_dtls

import (
	"encoding/hex"
	"fmt"
	"testing"
)

func TestHandshakeConstruction(t *testing.T) {
	m := new(dtlsHandshake)
	var u dtlsHandshake

	// build dtlsHandshake struct
	m.handshakeType = HandshakeTypeClientHello
	m.messageSequence = 0x1234
	m.fragmentOffset = 0x5678
	m.fragmentLength = 0x90ab
	m.body = []byte{0xaa, 0xbb, 0xcc}

	buf := m.marshal()

	if u.unmarshal(buf) == false {
		t.Errorf("Unable to unmarshal buf")
		fmt.Println(hex.Dump(buf))
	}

	if !m.equal(&u) {
		t.Errorf("m != m.Marshal().Unmarshal()")
		fmt.Printf("%#v\n", m)
		fmt.Printf("%#v\n", u)
	}
}
