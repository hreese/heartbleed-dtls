package heartbleed_dtls

//import (
//	"encoding/hex"
//	"fmt"
//	"testing"
//)

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
