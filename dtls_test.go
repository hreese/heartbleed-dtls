package heartbleed_dtls

import (
	_ "encoding/binary"
	"encoding/hex"
	"fmt"
	_ "net"
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

	if !m.Equal(u) {
		t.Errorf("m != m.Marshal().Unmarshal()")
		fmt.Printf("%#v\n", m)
		fmt.Printf("%#v\n", u)
	}
}

func TestClientHelloMsgConstruction(t *testing.T) {
    h1 := dtlsClientHelloMsg{
        nil,
        VersionDTLS10,
        []byte{ 0xd0, 0xdc, 0x8d, 0xd8, 0x9c, 0x6, 0xcc, 0x32, 0x8f, 0xcd, 0x28,
        0x3b, 0xea, 0xe9, 0x3d, 0xf3, 0x4d, 0xed, 0x67, 0xbe, 0xb4, 0x5d, 0xdc,
        0xb8, 0x45, 0xdd, 0x55, 0x1b, 0xf9, 0x9c, 0x3a, 0x80, },
        nil,
        nil,
        []uint16{ 1, 2, 4, 5, 7, 9, 0x0a, },
        []uint8{ 0 },
        false,
        "",
        nil,
        nil,
        false,
        nil,
        1,
    }
    p1 := h1.marshal()
    fmt.Println(hex.Dump(p1))
}

//func TestClientAgainstServer(t *testing.T) {
//    buf, _ := BuildClientHello(0, DTLSv10, [][]byte{ClientHelloHandshakeHeartbeatExt})
//    pbuf   := BuildDTLSRecord(ContentTypeHandshake, DTLSv10, 0, 0, buf)
//
//    conn, err := net.Dial("udp", "localhost:4433"); if err != nil {
//        t.Error(err)
//    }
//    defer conn.Close()
//
//    fmt.Println(hex.Dump(pbuf))
//    conn.Write(pbuf)
//
//    // TODO: read and process answer
//}
