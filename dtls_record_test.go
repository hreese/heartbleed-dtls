package heartbleed_dtls

import (
	"bytes"
	_ "encoding/binary"
	"encoding/hex"
	"fmt"
    "net"
    "testing"
)

type U16BytesTest struct {
    number uint32
    result []byte
}

func TestEmptyDTLSRecord(t *testing.T) {
	emptyRecord := BuildDTLSRecord(ContentTypeHandshake, DTLSv10, 0, 0, nil)
    //hexdump := hex.EncodeToString(emptyRecord)
    //fmt.Println(hexdump)
    length := len(emptyRecord)
    if length != 13 {
        t.Error("Empty record is ", length, " bytes long, expexted 13")
    }
}

func TestSomeDTLSRecord(t *testing.T) {
    r1 := BuildDTLSRecord(ContentTypeHandshake, DTLSv10, 23,
    0xfedcba0987654321, []byte("Hello World!"))
    //fmt.Println(hex.EncodeToString(r1))
    refrec := []byte{ 0x16, 0xfe, 0xff, 0x00, 0x17, 0xba, 0x09, 0x87, 0x65,
    0x43, 0x21, 0x00, 0x0c, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f,
    0x72, 0x6c, 0x64, 0x21 }
    if bytes.Compare(r1, refrec) != 0 {
        t.Error("r1 does not look like the reference")
    }
}

//func TestClientHello(t *testing.T) {
//    buf, _ := BuildClientHello(0, DTLSv10, [][]byte{ClientHelloHandshakeHeartbeatExt})
//    fmt.Println(hex.Dump(buf))
//}

func TestClientAgainstServer(t *testing.T) {
    buf, _ := BuildClientHello(0, DTLSv10, [][]byte{ClientHelloHandshakeHeartbeatExt})
    pbuf   := BuildDTLSRecord(ContentTypeHandshake, DTLSv10, 0, 0, buf)

    conn, err := net.Dial("udp", "localhost:4433"); if err != nil {
        t.Error(err)
    }
    defer conn.Close()
    
    fmt.Println(hex.Dump(pbuf))
    conn.Write(pbuf)
    
    // TODO: read and process answer
}

func TestUint32To3Bytes(t *testing.T) {
    tests := []U16BytesTest {
        {0x00000000, []byte{ 0x00, 0x00, 0x00, }},
        {0x00000001, []byte{ 0x00, 0x00, 0x01, }},
        {0x0000000f, []byte{ 0x00, 0x00, 0x0f, }},
        {0x00ffffff, []byte{ 0xff, 0xff, 0xff, }},
    }
    for i := range(tests) {
        result := Uint32To3Bytes(tests[i].number)
        if bytes.Compare(result, tests[i].result) != 0 {
            t.Errorf("Error converting %#v to bytearray; got %#v; expected %#v\n",
            tests[i].number, result, tests[i].result)
        }
    }
}
