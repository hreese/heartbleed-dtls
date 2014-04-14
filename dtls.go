package heartbleed_dtls

import (
	"bytes"
	_ "crypto/rand"
	_ "encoding/binary"
	_ "encoding/hex"
	_ "fmt"
	_ "time"
)

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
	buf[10] = uint8(m.fragmentLength >> 24)
	buf[11] = uint8(m.fragmentLength >> 16)
	buf[12] = uint8(m.fragmentLength >> 8)
	buf[13] = uint8(m.fragmentLength)
	copy(buf[14:], m.body)

	m.raw = buf

	return buf
}

type dtlsClientHelloMsg struct {
	raw                []byte
	version            uint16
	random             []byte   // (32)
	sessionId          []byte   // 1+v
	cookie             []byte   // 1+v
	cipherSuites       []uint16 // 2+v
	compressionMethods []uint8  // 2+v
	ocspStapling       bool
	serverName         string
	supportedCurves    []uint16
	supportedPoints    []uint8
	ticketSupported    bool
	sessionTicket      []uint8
	heartbeat          uint8
}

func (m *dtlsClientHelloMsg) marshal() []byte {
	if m.raw != nil {
		return m.raw
	}

	length := 2 + 32 + 1 + len(m.sessionId) + 1 + len(m.cookie) + 2 + len(m.cipherSuites)*2 + len(m.compressionMethods)
	numExtensions := 0
	extensionsLength := 0

	if m.ocspStapling {
		extensionsLength += 1 + 2 + 2
		numExtensions++
	}
	if len(m.serverName) > 0 {
		extensionsLength += 5 + len(m.serverName)
		numExtensions++
	}
	if len(m.supportedCurves) > 0 {
		extensionsLength += 2 + 2*len(m.supportedCurves)
		numExtensions++
	}
	if len(m.supportedPoints) > 0 {
		extensionsLength += 1 + len(m.supportedPoints)
		numExtensions++
	}
	if m.ticketSupported {
		extensionsLength += len(m.sessionTicket)
		numExtensions++
	}
    if m.heartbeat > 0 {
        extensionsLength += 1
        numExtensions++
    }
	if numExtensions > 0 {
		extensionsLength += 4 * numExtensions
		length += 2 + extensionsLength
	}

    x := make([]byte, 4+length)
    x[0] = HandshakeTypeHelloRequest
    x[1] = uint8(length >> 16)
    x[2] = uint8(length >> 8)
    x[3] = uint8(length)
    x[4] = uint8(m.version >> 8)
    x[5] = uint8(m.version)
    copy(x[6:38], m.random)
    x[38] = uint8(len(m.sessionId))
    copy(x[39:39+len(m.sessionId)], m.sessionId)
    y := x[39+len(m.sessionId):]
    y[0] = uint8(len(m.cipherSuites) >> 7)
    y[1] = uint8(len(m.cipherSuites) << 1)
    for i, suite := range m.cipherSuites {
        y[2+i*2] = uint8(suite >> 8)
        y[3+i*2] = uint8(suite)
    }
    z := y[2+len(m.cipherSuites)*2:]
    z[0] = uint8(len(m.compressionMethods))
    copy(z[1:], m.compressionMethods)

    z = z[1+len(m.compressionMethods):]
    if numExtensions > 0 {
        z[0] = byte(extensionsLength >> 8)
        z[1] = byte(extensionsLength)
        z = z[2:]
    }

	if len(m.serverName) > 0 {
		z[0] = byte(extensionServerName >> 8)
		z[1] = byte(extensionServerName)
		l := len(m.serverName) + 5
		z[2] = byte(l >> 8)
		z[3] = byte(l)
		z = z[4:]

		z[0] = byte((len(m.serverName) + 3) >> 8)
		z[1] = byte(len(m.serverName) + 3)
		z[3] = byte(len(m.serverName) >> 8)
		z[4] = byte(len(m.serverName))
		copy(z[5:], []byte(m.serverName))
		z = z[l:]
	}
	if m.ocspStapling {
		// RFC 4366, section 3.6
		z[0] = byte(extensionStatusRequest >> 8)
		z[1] = byte(extensionStatusRequest)
		z[2] = 0
		z[3] = 5
		z[4] = 1 // OCSP type
		// Two zero valued uint16s for the two lengths.
		z = z[9:]
	}
	if len(m.supportedCurves) > 0 {
		// http://tools.ietf.org/html/rfc4492#section-5.5.1
		z[0] = byte(extensionSupportedCurves >> 8)
		z[1] = byte(extensionSupportedCurves)
		l := 2 + 2*len(m.supportedCurves)
		z[2] = byte(l >> 8)
		z[3] = byte(l)
		l -= 2
		z[4] = byte(l >> 8)
		z[5] = byte(l)
		z = z[6:]
		for _, curve := range m.supportedCurves {
			z[0] = byte(curve >> 8)
			z[1] = byte(curve)
			z = z[2:]
		}
	}
	if len(m.supportedPoints) > 0 {
		// http://tools.ietf.org/html/rfc4492#section-5.5.2
		z[0] = byte(extensionSupportedPoints >> 8)
		z[1] = byte(extensionSupportedPoints)
		l := 1 + len(m.supportedPoints)
		z[2] = byte(l >> 8)
		z[3] = byte(l)
		l--
		z[4] = byte(l)
		z = z[5:]
		for _, pointFormat := range m.supportedPoints {
			z[0] = byte(pointFormat)
			z = z[1:]
		}
	}
	if m.ticketSupported {
		// http://tools.ietf.org/html/rfc5077#section-3.2
		z[0] = byte(extensionSessionTicket >> 8)
		z[1] = byte(extensionSessionTicket)
		l := len(m.sessionTicket)
		z[2] = byte(l >> 8)
		z[3] = byte(l)
		z = z[4:]
		copy(z, m.sessionTicket)
		z = z[len(m.sessionTicket):]
	}
    if m.heartbeat > 0 {
        z[0] = byte(extensionHeartbeat >> 8)
        z[1] = byte(extensionHeartbeat)
        z[2] = m.heartbeat
    }

	m.raw = x

	return x
}
