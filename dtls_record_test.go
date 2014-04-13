package heartbleed_dtls

import (
	"bytes"
	_ "encoding/binary"
	"encoding/hex"
	"fmt"
    _ "net"
    "testing"
)

type U16BytesTest struct {
    number uint32
    result []byte
}

func TestHandshake(t *testing.T) {
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

//func TestClientHello(t *testing.T) {
//    buf, _ := BuildClientHello(0, DTLSv10, [][]byte{ClientHelloHandshakeHeartbeatExt})
//    fmt.Println(hex.Dump(buf))
//}

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
