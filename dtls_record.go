package heartbleed_dtls

import (
	"bytes"
    "crypto/rand"
	"encoding/binary"
	_ "encoding/hex"
    "fmt"
    "time"
)

// DTLS record types
const (
    RecordTypeChangeCypherSpec uint8      = 20
    RecordTypeAlert uint8                 = 21
    RecordTypeHandshake uint8             = 22
    RecordTypeApplicationData uint8       = 23
    VersionDTLS10 uint16                  = 0xfeff
    VersionDTLS12 uint16                  = 0xfefd
    HandshakeTypeHelloRequest uint8       = 0
    HandshakeTypeClientHello uint8        = 1
    HandshakeTypeServerHello uint8        = 2
    HandshakeTypeHelloVerifyRequest uint8 = 3
    HandshakeTypeCertificate uint8        = 11
    HandshakeTypeServerKeyExchange uint8  = 12
    HandshakeTypeCertificateRequest uint8 = 13
    HandshakeTypeServerHelloDone uint8    = 14
    HandshakeTypeCertificateVerify uint8  = 15
    HandshakeTypeClientKeyExchange uint8  = 16
    HandshakeTypeFinished uint8           = 20
)

type dtlsHandshake struct {
    raw             []byte
    handshakeType   uint8
    length          uint32 // 3 bytes
    messageSequence uint16
    fragmentOffset  uint32
    fragmentLength  uint32
    body            []byte
}

func (m *dtlsHandshake) Equal(i interface{}) bool {
    m1, ok := i.(dtlsHandshake)
    if !ok {
        return false
    }

    return bytes.Equal(m.raw, m1.raw) &&
        m.handshakeType == m.handshakeType &&
        m.length == m.length &&
        m.messageSequence == m.messageSequence &&
        m.fragmentOffset == m.fragmentOffset &&
        m.fragmentLength == m.fragmentLength &&
        bytes.Equal(m.body, m1.body)
}

func (m *dtlsHandshake) unmarshal(data []byte) bool {
    if len(data) < 14 {
        return false
    }
    m.raw = data
    m.handshakeType = uint8(data[0])
    m.length = uint32(data[1])<<16 | uint32(data[2])<<8 | uint32(data[3])
    if uint32(len(data)) != 4 + m.length {
        return false
    }
    m.messageSequence = uint16(data[4])<<8 | uint16(data[5])
    m.fragmentOffset = uint32(data[6])<<24 | uint32(data[7])<<16 | uint32(data[8])<<8 | uint32(data[9])
    m.fragmentLength = uint32(data[10])<<24 | uint32(data[11])<<16 | uint32(data[12])<<8 | uint32(data[13])
    m.body = make([]byte, len(data[14:]))
    copy(m.body, data[14:])

    return true
}

func (m *dtlsHandshake) marshal() []byte {
    if m.raw != nil {
        return m.raw
    }

    length := 10 + len(m.body)
    m.length = uint32(length)

    buf := make([]byte, 4 + length)

    buf[0]  = m.handshakeType
    buf[1]  = uint8(length >> 16)
    buf[2]  = uint8(length >> 8)
    buf[3]  = uint8(length)
    buf[4]  = uint8(m.messageSequence >> 8)
    buf[5]  = uint8(m.messageSequence)
    buf[6]  = uint8(m.fragmentOffset >> 24)
    buf[7]  = uint8(m.fragmentOffset >> 16)
    buf[8]  = uint8(m.fragmentOffset >> 8)
    buf[9]  = uint8(m.fragmentOffset)
    buf[10] = uint8(m.fragmentLength >> 24)
    buf[11] = uint8(m.fragmentLength >> 16)
    buf[12] = uint8(m.fragmentLength >> 8)
    buf[13] = uint8(m.fragmentLength)
    copy(buf[14:], m.body)

    m.raw = buf

    return buf
}

type dtlsClientHelloMsg struct {
    version uint16
    epoch uint32
    random []byte
    sessionId []byte
    cookie []byte
    cipherSuites []uint16
    compressionMethods []uint8
    
}

var ClientHelloHandshakePart3 = []byte{
    // version [2 bytes]
    // epoch [4 bytes]
    // random [28 bytes]
    0x00,                         // Session ID Length: 0
    0x00,                         // Cookie Length: 0
    0x00, 0x40,                   // Cipher Suites Length: 64
    0xc0, 0x14, 0xc0, 0x0a, 0x00, 0x39, 0x00, 0x38, 0x00, 0x88, 0x00, 0x87,
    0xc0, 0x0f, 0xc0, 0x05, 0x00, 0x35, 0x00, 0x84, 0xc0, 0x12, 0xc0, 0x08,
    0x00, 0x16, 0x00, 0x13, 0xc0, 0x0d, 0xc0, 0x03, 0x00, 0x0a, 0xc0, 0x13,
    0xc0, 0x09, 0x00, 0x33, 0x00, 0x32, 0x00, 0x9a, 0x00, 0x99, 0x00, 0x45,
    0x00, 0x44, 0xc0, 0x0e, 0xc0, 0x04, 0x00, 0x2f, 0x00, 0x96, 0x00, 0x41,
    0x00, 0x07, 0x00, 0xff,       // Cipher Suites (32 suites)
    0x01,                         // Compression Methods Length: 1
    0x00,                         // Compression Methods (1 method)
    // Extensions Length [2 bytes] <- correct this
    // Extensions [variable length]
}

var ClientHelloHandshakeHeartbeatExt = []byte{
    0x00, 0x0f, 0x00, 0x01, 0x01, // Extension: Heartbeat
}

func BuildClientHello(msgseq uint16, version int, extensions [][]byte) (packet, random []byte) {
	buf := bytes.Buffer{}

    // add handshake type and length
    ///// buf.Write(ClientHelloHandshakePart1)

    // add message sequence, fragment offset and fragment length
    buf.Write(Uint16To2Bytes(uint16(msgseq)))
    ///// buf.Write(ClientHelloHandshakePart2)

    // add version
    buf.Write(Uint16To2Bytes(uint16(version)))

    // generate and add timestamp
    epoch := uint32(time.Now().Unix())
    epochbuf := make([]byte, 4)
    binary.BigEndian.PutUint32(epochbuf, epoch)
    buf.Write(epochbuf)

    // generate and add random bytes
    randbuf := make([]byte, 28)
    rand.Read(randbuf)
    buf.Write(randbuf)

    // add last handshake part
    buf.Write(ClientHelloHandshakePart3)

    // build extension (last part of the packet)
	extbuf := bytes.Buffer{}
    var extlen uint16 = 0
    for i := range(extensions) {
        extbuf.Write(extensions[i])
        extlen += uint16(len(extensions[i]))
    }

    // add extension length and extensions
    buf.Write(Uint16To2Bytes(extlen))
    buf.Write(extbuf.Bytes())

    // fix lengths/offsets
    Packet := buf.Bytes()
    PacketLength := len(Packet)
    Length := Uint32To3Bytes(uint32(PacketLength-4)-8)
    FragmentLength := Uint32To3Bytes(uint32(PacketLength-12))
    //fmt.Printf("%#v\n", Length)
    //fmt.Printf("%#v\n", FragmentLength)

    slice := Packet[1:4]
    copy(slice, Length)
    slice = Packet[9:12]
    copy(slice, FragmentLength)

    return Packet, randbuf
}

func Uint32To3Bytes(in uint32) []byte {
    if in > 256*256*256 {
        panic(fmt.Errorf("Unable to convert uint32 %d to a [3]byte", in))
    }
    buf := make([]byte, 4)
    binary.BigEndian.PutUint32(buf, in)
    return buf[1:4]
}

func Uint16To2Bytes(in uint16) []byte {
    buf := make([]byte, 2)
    binary.BigEndian.PutUint16(buf, in)
    return buf
}

func BuildDTLSRecord(ContentType []byte, ProtocolVersion int, epoch uint16, seqnum uint64, fragment []byte) []byte {
	buf := bytes.Buffer{}

    // add ContentType
	buf.Write(ContentType)

    // add ProtocolVersion
    buf.Write(Uint16To2Bytes(uint16(ProtocolVersion)))

    // add epoch
    epochbuf := make([]byte, 2)
    binary.BigEndian.PutUint16(epochbuf, epoch)

    buf.Write(epochbuf)

    // add sequence number
    sequencebuf := make([]byte, 8)
    binary.BigEndian.PutUint64(sequencebuf, seqnum)

    buf.Write(sequencebuf[2:8])

    // calculate length of fragment and add length
    length64 := len(fragment)
    if length64 > 256*256 {
        panic("Fragment is too large.")
    }
    length16 := uint16(length64)
    lenbuf := make([]byte, 2)
    binary.BigEndian.PutUint16(lenbuf, length16)

    buf.Write(lenbuf)

    // add fragment
	buf.Write(fragment)

	return buf.Bytes()
}

