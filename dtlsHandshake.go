package heartbleed_dtls

import (
	"bytes"
	"encoding/hex"
	"fmt"
)

type dtlsHandshake struct {
	raw             []byte
	handshakeType   uint8
	length          uint32 // uint24
	messageSequence uint16
	fragmentOffset  uint32
	fragmentLength  uint32
	body            []byte
}

func (m *dtlsHandshake) equal(i interface{}) bool {
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
	if len(data) < 14 {
		return false
	}
	m.raw = data
	m.handshakeType = uint8(data[0])
	m.length = uint32(data[1])<<16 | uint32(data[2])<<8 | uint32(data[3])
	if uint32(len(data)) != 4+m.length {
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

	buf := make([]byte, 4+length)

	fmt.Printf("%#v\n", m)
	fmt.Println(hex.Dump(buf))
	buf[0] = m.handshakeType
	buf[1] = uint8(length >> 16)
	buf[2] = uint8(length >> 8)
	buf[3] = uint8(length)
	buf[4] = uint8(m.messageSequence >> 8)
	buf[5] = uint8(m.messageSequence)
	buf[6] = uint8(m.fragmentOffset >> 24)
	buf[7] = uint8(m.fragmentOffset >> 16)
	buf[8] = uint8(m.fragmentOffset >> 8)
	buf[9] = uint8(m.fragmentOffset)
	if m.fragmentLength == 0 {
		m.fragmentLength = uint32(len(m.body))
		fmt.Printf("New length: %d\n", m.fragmentLength)
	}
	buf[10] = uint8(m.fragmentLength >> 24)
	buf[11] = uint8(m.fragmentLength >> 16)
	buf[12] = uint8(m.fragmentLength >> 8)
	buf[13] = uint8(m.fragmentLength)
	fmt.Printf("%#v\n", m)
	fmt.Println(hex.Dump(buf))
	copy(buf[14:], m.body)

	m.raw = buf

	return buf
}
