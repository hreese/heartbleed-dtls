package heartbleed_dtls

import (
	"bytes"
    "crypto/rand"
	"encoding/binary"
    "time"
)

var ContentTypeChangeCypherSpec = []byte{20}
var ContentTypeAlter = []byte{21}
var ContentTypeHandshake = []byte{22}
var ContentTypeApplicationData = []byte{23}
var HandshakeDTLSVersion = []byte{0xfe, 0xff}

var ClientHelloHandshakePart1 = []byte{
    0x01,             // Handshake Type: Client Hello (1)
    0x00, 0x00, 0x6f, // Length: 111
    0x00, 0x00,       // Message Sequence: 0
    0x00, 0x00, 0x00, // Fragment Offset: 0
    0x00, 0x00, 0x6f, // Fragment Length: 111
    0xfe, 0xff,       // Version: DTLS 1.0 (0xfeff)
} 

var ClientHelloHandshakePart2 = []byte{
    0x00,                         // Session ID Length: 0
    0x00,                         // Cookie Length: 0
    0x00, 0x40,                   // Cipher Suites Length: 64
    0xc0, 0x14, 0xc0, 0x0a, 0x00, 0x39, 0x00, 0x38 , 0x00, 0x88, 0x00, 0x87,
    0xc0, 0x0f, 0xc0, 0x05, 0x00, 0x35, 0x00, 0x84, 0xc0, 0x12, 0xc0, 0x08,
    0x00, 0x16, 0x00, 0x13, 0xc0, 0x0d, 0xc0, 0x03, 0x00, 0x0a, 0xc0, 0x13,
    0xc0, 0x09, 0x00, 0x33, 0x00, 0x32, 0x00, 0x9a, 0x00, 0x99, 0x00, 0x45,
    0x00, 0x44, 0xc0, 0x0e, 0xc0, 0x04, 0x00, 0x2f, 0x00, 0x96, 0x00, 0x41,
    0x00, 0x07, 0x00, 0xff,       // Cipher Suites (32 suites)
    0x01,                         // Compression Methods Length: 1
    0x00,                         // Compression Methods (1 method)
    0x00, 0x05,                   // Extensions Length: 9
    0x00, 0x0f, 0x00, 0x01, 0x01, // Extension: Heartbeat
}

func BuildDTLSRecord(ContentType, ProtocolVersion []byte, epoch uint16, seqnum uint64, fragment []byte) []byte {
	buf := bytes.Buffer{}

    // add ContentType
	_, err := buf.Write(ContentType)
	if err != nil {
		panic(err)
	}

    // add ProtocolVersion
	_, err = buf.Write(ProtocolVersion)
	if err != nil {
		panic(err)
	}

    // add epoch
    epochbuf := make([]byte, 2)
    binary.BigEndian.PutUint16(epochbuf, epoch)

    _, err = buf.Write(epochbuf)
	if err != nil {
		panic(err)
	}

    // add sequence number
    sequencebuf := make([]byte, 8)
    binary.BigEndian.PutUint64(sequencebuf, seqnum)

    _, err = buf.Write(sequencebuf[2:8])
	if err != nil {
		panic(err)
	}

    // calculate length of fragment and add length
    length64 := len(fragment)
    if length64 > 2^16-1 {
        panic("Fragment is too large.")
    }
    length16 := uint16(length64)
    lenbuf := make([]byte, 2)
    binary.BigEndian.PutUint16(lenbuf, length16)
	
    _, err = buf.Write(lenbuf)
	if err != nil {
		panic(err)
	}

    // add fragment
	_, err = buf.Write(fragment)
	if err != nil {
		panic(err)
	}

	return buf.Bytes()
}

func BuildClientHello() (packet, random []byte) {
	buf := bytes.Buffer{}

    // add first constand part of handshake
    _, err := buf.Write(ClientHelloHandshakePart1)
	if err != nil {
		panic(err)
	}

    // add timestamp
    epoch := uint32(time.Now().Unix())
    epochbuf := make([]byte, 4)
    binary.BigEndian.PutUint32(epochbuf, epoch)
    
    _, err = buf.Write(epochbuf)
	if err != nil {
		panic(err)
	}

    // add random bytes
    randbuf := make([]byte, 28)
    _, err = rand.Read(randbuf)
	if err != nil {
		panic(err)
	}

    _, err = buf.Write(randbuf)
	if err != nil {
		panic(err)
	}

    // add second constand part of handshake
    _, err = buf.Write(ClientHelloHandshakePart2)
	if err != nil {
		panic(err)
	}

    return buf.Bytes(), randbuf
}

