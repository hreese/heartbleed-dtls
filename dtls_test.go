package heartbleed_dtls

import (
    "bytes"
    "crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"testing"
)

// Test 1: simple package, empty body
func TestRecordConstruction1(t *testing.T) {
    r1 := dtlsRecord{
        raw: nil,
        contentType: HandshakeTypeClientHello,
        version: VersionDTLS12,
        dtlsBody: nil,
    }

    r1_bref := []byte{
        0x01,
        0xfe, 0xfd,
        0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 
    }
    r1b := r1.marshal()
    if !bytes.Equal(r1_bref, r1b) {
        t.Errorf("Error in dtlsRecord.marshal()")
		fmt.Println(hex.Dump(r1_bref))
		fmt.Println(hex.Dump(r1b))
    }
}

// Test 2: random body, nonempty fields when possible
func TestRecordConstruction2(t *testing.T) {
    body := make([]byte, 512)
    _, err := rand.Read(body); if err != nil {
        t.Errorf("Unable to Read() from crypto/rand.")
    }

    r2 := dtlsRecord{
        raw: nil,
        contentType: HandshakeTypeFinished,
        version: VersionDTLS10,
        epoch: 0xabcd,
        sequenceNumber: 0x00001234567890ab,
        length: 0,
        dtlsBody: body,
    }

    r2_bref := make([]byte, 13+512)
    r2_bref_header := []byte {
        0x14,
        0xfe, 0xff,
        0xab, 0xcd,
        0x12, 0x34, 0x56, 0x78, 0x90, 0xab,
        0x02, 0x00,
    }
    copy(r2_bref[0:], r2_bref_header)
    copy(r2_bref[13:], body)

    r2b := r2.marshal()
    if !bytes.Equal(r2_bref, r2b) {
        t.Errorf("Error in dtlsRecord.marshal()")
        fmt.Print("packet:\n", hex.Dump(r2b))
        fmt.Print("reference:\n", hex.Dump(r2_bref))
    }

    // marshaling a packet twice should yield the same result (caching)
    r2b_again := r2.marshal()
    if !bytes.Equal(r2_bref, r2b_again) {
        t.Errorf("Error in dtlsRecord.marshal() when dtlsRecord was already marshalled")
        fmt.Print("packet:\n", hex.Dump(r2b))
        fmt.Print("reference:\n", hex.Dump(r2_bref))
    }
}

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
