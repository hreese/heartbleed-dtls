package handshake

import (
	"bytes"
	_ "encoding/hex"
	_ "fmt"
)

type dtlsHandshake struct {
	raw             []byte
	handshakeType   uint8
	length          uint32 // uint24, length of body (all fragments) in bytes
	messageSequence uint16
	fragmentOffset  uint32 // uint24
	fragmentLength  uint32 // uint24, length of fragment in this fragment
	body            []byte
}

func (m *dtlsHandshake) Equal(i interface{}) bool {
	m1, ok := i.(*dtlsHandshake)
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
	if len(data) < 12 {
		return false
	}
	m.raw = data
	m.handshakeType = uint8(data[0])
	m.length = uint32(data[1])<<16 | uint32(data[2])<<8 | uint32(data[3])
	m.messageSequence = uint16(data[4])<<8 | uint16(data[5])
	m.fragmentOffset = uint32(data[6])<<16 | uint32(data[7])<<8 | uint32(data[8])
	m.fragmentLength = uint32(data[9])<<16 | uint32(data[10])<<8 | uint32(data[11])
	if uint32(len(data)) != 12+m.fragmentLength {
		return false
	}
	m.body = make([]byte, len(data[12:]))
	copy(m.body, data[12:])

	return true
}

func (m *dtlsHandshake) marshal() []byte {
	if m.raw != nil {
		return m.raw
	}

	length := len(m.body)
	if m.fragmentLength == 0 {
		m.fragmentLength = uint32(length)
	}

	if m.length == 0 {
		m.length = m.fragmentLength
	}

	buf := make([]byte, 12+length)

	//fmt.Printf("%#v\n", m)
	//fmt.Println(hex.Dump(buf))
	buf[0] = m.handshakeType
	buf[1] = uint8(m.length >> 16)
	buf[2] = uint8(m.length >> 8)
	buf[3] = uint8(m.length)
	buf[4] = uint8(m.messageSequence >> 8)
	buf[5] = uint8(m.messageSequence)
	buf[6] = uint8(m.fragmentOffset >> 16)
	buf[7] = uint8(m.fragmentOffset >> 8)
	buf[8] = uint8(m.fragmentOffset)
	buf[9] = uint8(m.fragmentLength >> 16)
	buf[10] = uint8(m.fragmentLength >> 8)
	buf[11] = uint8(m.fragmentLength)
	//fmt.Printf("%#v\n", m)
	//fmt.Println(hex.Dump(buf))
	copy(buf[12:], m.body)

	m.raw = buf

	return buf
}
