package heartbleed_dtls

import (
	"bytes"
	_ "crypto/rand"
	_ "encoding/binary"
	"encoding/hex"
	"fmt"
	_ "time"
)

func (m *dtlsRecord) marshal() []byte {
	if m.raw != nil {
		return m.raw
	}

	m.length = uint16(len(m.dtlsBody))

	buf := make([]byte, 13+m.length)

	buf[0] = m.contentType
	buf[1] = uint8(m.version >> 8)
	buf[2] = uint8(m.version)
	buf[3] = uint8(m.epoch >> 8)
	buf[4] = uint8(m.epoch)
	buf[5] = uint8(m.sequenceNumber >> 40)
	buf[6] = uint8(m.sequenceNumber >> 32)
	buf[7] = uint8(m.sequenceNumber >> 24)
	buf[8] = uint8(m.sequenceNumber >> 16)
	buf[9] = uint8(m.sequenceNumber >> 8)
	buf[10] = uint8(m.sequenceNumber)
	buf[11] = uint8(m.length >> 8)
	buf[12] = uint8(m.length)

	copy(buf[13:], m.dtlsBody)

	m.raw = buf

	return buf
}

func (m *dtlsRecord) unmarshal(data []byte) bool {
	if len(data) < 13 {
		return false
	}
	m.raw = data
	m.contentType = uint8(data[0])
	m.version = uint16(data[1])<<8 | uint16(data[2])
	m.epoch = uint16(data[3])<<8 | uint16(data[4])
	m.sequenceNumber = uint64(data[5])<<40 | uint64(data[6])<<32 | uint64(data[7])<<24 | uint64(data[8])<<16 | uint64(data[9])<<8 | uint64(data[10])
	m.length = uint16(data[11])<<8 | uint16(data[12])

	copy(m.dtlsBody, data[12:])

	return true
}

func (m *dtlsRecord) Equal(i interface{}) bool {
	m1, ok := i.(dtlsRecord)
	if !ok {
		return false
	}

	return bytes.Equal(m.raw, m1.raw) &&
		m.contentType == m.contentType &&
		m.version == m.version &&
		m.epoch == m.epoch &&
		m.sequenceNumber == m.sequenceNumber &&
		m.length == m.length &&
		bytes.Equal(m.dtlsBody, m1.dtlsBody)
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

func (m *dtlsClientHelloMsg) marshal() []byte {
	if m.raw != nil {
		return m.raw
	}

	length := 2 + 32 + 1 + len(m.sessionId) + 1 + len(m.cookie) + 2 + len(m.cipherSuites)*2 + len(m.compressionMethods)
	numExtensions := 0
	extensionsLength := 0

	fmt.Printf("001: %#v %#v %#v\n", length, numExtensions, extensionsLength)

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
	if m.heartbeat > 0 {
		extensionsLength += 1
		numExtensions++
	}
	if numExtensions > 0 {
		extensionsLength += 4 * numExtensions
		length += 2 + extensionsLength
	}

	fmt.Printf("002: %#v %#v %#v\n", length, numExtensions, extensionsLength)

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
	if m.heartbeat > 0 {
		z[0] = byte(extensionHeartbeat >> 8)
		z[1] = byte(extensionHeartbeat)
		z[2] = m.heartbeat
	}

	m.raw = x

	return x
}
