package heartbleed_dtls

import (
	"encoding/hex"
	"fmt"
	"net"
	"testing"
)

func TestClientHelloMsgConstruction(t *testing.T) {
	p1 := dtlsMinimalClientHelloMsg.marshal()
	fmt.Println(hex.Dump(p1))

	// handshake frame
	mHandshake := new(dtlsHandshake)
	mHandshake.handshakeType = HandshakeTypeClientHello
	mHandshake.body = p1
	p2 := mHandshake.marshal()
	fmt.Println(hex.Dump(p2))

	// record frame
	mRecord := new(dtlsRecord)
	mRecord.contentType = TypeHandshake
	mRecord.version = VersionDTLS10
	mRecord.dtlsBody = p2

	// udp connection
	conn, err := net.Dial("udp", "localhost:4433")
	if err != nil {
		t.Error(err)
	}
	defer conn.Close()
	p3 := mRecord.marshal()
	conn.Write(p3)

	fmt.Println(hex.Dump(p3))
}
