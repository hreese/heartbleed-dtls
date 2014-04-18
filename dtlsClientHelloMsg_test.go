package heartbleed_dtls

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"net"
	"testing"
)

func TestClientHelloMsgConstruction(t *testing.T) {
	m := new(dtlsClientHelloMsg)

	m.version = VersionDTLS10
	m.random = NewRandom()
	//m.sessionId = []byte{0x88, 0x88}
	m.sessionId = nil
	m.cookie = nil
	m.cipherSuites = []uint16{0x0013} // TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA
	m.compressionMethods = []uint8{0}
	m.ocspStapling = false
	m.serverName = ""
	m.supportedCurves = nil
	m.supportedPoints = nil
	m.ticketSupported = false
	m.heartbeat = 1

	if !m.Equal(m) {
		t.Errorf("dtlsClientHelloMsg not equal() to itself")
	}

	ref := dtlsClientHelloMsg{
		raw:                nil,
		version:            0xfeff,
		sessionId:          nil,
		cookie:             nil,
		cipherSuites:       []uint16{0x13},
		compressionMethods: []byte{0x00},
		ocspStapling:       false,
		serverName:         "",
		supportedCurves:    nil,
		supportedPoints:    nil,
		ticketSupported:    false,
		heartbeat:          0x01,
	}
	copy(ref.random, m.random)

	bref := []byte{
		0xfe, 0xff, // version
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0x00,                   // sessionId
		0x00,                   // cookie
		0x00, 0x02, 0x00, 0x13, // cipherSuites
		0x01, 0x00, // compressionMethods
		0x00, 0x05, // extension length
		0x00, 0x0f, 0x00, 0x01, 0x01,
	}
	copy(bref[2:], m.random)

	buf := m.marshal()
	if !bytes.Equal(buf, bref) {
		t.Errorf("a.marshal() => b, want c\n")
		fmt.Printf("a: %#+v\n", m)
		hdb, hdc, hddiff, places := VisuallyCompareByteArray(buf, bref)
		fmt.Print("b:\n" + hdb)
		fmt.Print("c:\n" + hdc)
		fmt.Print("diff:\n" + hddiff)
		fmt.Print("Details of differences:\n" + places)
	}
}

func TestClientHelloMsgSending(t *testing.T) {
	p1 := dtlsMinimalClientHelloMsg.marshal()

	fmt.Print(hex.Dump(p1))

	// handshake frame
	mHandshake := new(dtlsHandshake)
	mHandshake.handshakeType = HandshakeTypeClientHello
	mHandshake.body = p1
	p2 := mHandshake.marshal()

	// record frame
	mRecord := new(dtlsRecord)
	mRecord.contentType = TypeHandshake
	mRecord.version = VersionDTLS10
	mRecord.dtlsBody = p2
	p3 := mRecord.marshal()

	// udp connection
	conn, err := net.Dial("udp", "localhost:4433")
	if err != nil {
		t.Error(err)
	}
	defer conn.Close()
	conn.Write(p3)
}
