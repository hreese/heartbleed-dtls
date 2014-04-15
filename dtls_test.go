package heartbleed_dtls

import (
	_ "encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
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
	p1 := dtlsMinimalClientHelloMsg.marshal()

	// handshake frame
	mHandshake := new(dtlsHandshake)
	mHandshake.handshakeType = HandshakeTypeClientHello
	mHandshake.body = p1

	// record frame
	mRecord := new(dtlsRecord)
	mRecord.contentType = TypeHandshake
	mRecord.version = VersionDTLS10
	mRecord.dtlsBody = mHandshake.marshal()

	// udp connection
	conn, err := net.Dial("udp", "localhost:4433")
	if err != nil {
		t.Error(err)
	}
	defer conn.Close()
	conn.Write(mRecord.marshal())

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
//    conn.Write(pbuf)
//    fmt.Println(hex.Dump(pbuf))
//
//    // TODO: read and process answer
//}
