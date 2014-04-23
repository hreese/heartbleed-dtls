package handshake

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"reflect"
	"time"
)

func dontAnnoyMeWhileIAmDebugging() {
	fmt.Print(hex.Dump([]byte{0x23, 0x42}))
}

type dtlsHelloVerifyMsg struct {
	raw                []byte
	version            uint16
	cookie             []byte   // 1+v
}

func (m *dtlsHelloVerifyMsg) Equal(i interface{}) bool {
	m1, ok := i.(*dtlsHelloVerifyMsg)
	if !ok {
		return false
	}

	return bytes.Equal(m.raw, m1.raw) &&
		m.version == m1.version &&
		bytes.Equal(m.cookie, m1.cookie) &&
}

func (m *dtlsHelloVerifyMsg) marshal() []byte {
	if m.raw != nil {
		logClientHello.Print("raw not nil, returning raw.")
		return m.raw
	}

	length := 2 + 1 + len(m.cookie)

	x := make([]byte, length)
	x[0] = uint8(m.version >> 8)
	x[1] = uint8(m.version)

	x[2] = uint8(len(m.cookie))
	copy(x[3:3+len(m.cookie)], m.cookie)

	m.raw = x

	return x
}

func (m *dtlsHelloVerifyMsg) unmarshal(data []byte) bool {
    if len(data) < 3 {
        return false
    }

    m.raw = data

    m.version = uint16(data[0])<<8 | uint16(data[1])
    cookielength = uint8(data[2])
    if uint32(len(data)) != 3+cookielength {
        return false
    }

    m.cookie = make([]byte, cookielength)
    copy(m.cookie, data[3]

    return true
}
