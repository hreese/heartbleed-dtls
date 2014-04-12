//package heartbleed_dtls
package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"encoding/hex"
	//    _ "errors"
	//    _ "strings"
)

var ContentTypeChangeCypherSpec = []byte{20}
var ContentTypeAlter = []byte{21}
var ContentTypeHandshake = []byte{22}
var ContentTypeApplicationData = []byte{23}
var HandshakeDTLSVersion = []byte{0xfe, 0xff}

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

func main() {
	fmt.Println(hex.Dump(BuildDTLSRecord(ContentTypeHandshake,
		HandshakeDTLSVersion, 0, 0xfedcba0987654321, nil)))
}

// struct {
//   ContentType type;
//   ProtocolVersion version;
//   uint16 epoch;
//   uint48 sequence_number;
//   uint16 length;
//   opaque fragment[DTLSPlaintext.length];
// } DTLSPlaintext;
//func BuildDTLSHandshakeClientHello () []byte {
//}
