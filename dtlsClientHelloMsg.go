package heartbleed_dtls

import (
	"bytes"
	"crypto/rand"
    _ "encoding/hex"
	_ "fmt"
	"reflect"
	"time"
)

// RFC 4346, Section 7.4.1.2
func NewRandom() []byte {
	buf := make([]byte, 32)

	// add current time
	epoch := uint32(time.Now().Unix())
	buf[0] = byte(epoch >> 24)
	buf[1] = byte(epoch >> 16)
	buf[2] = byte(epoch >> 8)
	buf[3] = byte(epoch)

	// create random
	randbuf := make([]byte, 28)
	rand.Read(randbuf)
	copy(buf[3:], randbuf)

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
	heartbeat          uint8
}

func (m *dtlsClientHelloMsg) equal(i interface{}) bool {
	m1, ok := i.(*dtlsClientHelloMsg)
	if !ok {
		return false
	}

	return bytes.Equal(m.raw, m1.raw) &&
		m.version == m1.version &&
		bytes.Equal(m.random, m1.random) &&
		bytes.Equal(m.sessionId, m1.sessionId) &&
		bytes.Equal(m.cookie, m1.cookie) &&
		reflect.DeepEqual(m.cipherSuites, m1.cipherSuites) &&
		bytes.Equal(m.compressionMethods, m1.compressionMethods) &&
		m.ocspStapling == m1.ocspStapling &&
		m.serverName == m1.serverName &&
		reflect.DeepEqual(m.supportedCurves, m1.supportedCurves) &&
		bytes.Equal(m.supportedPoints, m1.supportedPoints) &&
		m.ticketSupported == m1.ticketSupported &&
		m.heartbeat == m1.heartbeat
}

func (m *dtlsClientHelloMsg) marshal() []byte {
	if m.raw != nil {
		return m.raw
	}

	length := 2 + 32 + 1 + len(m.sessionId) + 1 + len(m.cookie) + 2 + len(m.cipherSuites)*2 + 1+ len(m.compressionMethods)
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
	if m.heartbeat > 0 {
		extensionsLength += 1
		numExtensions++
	}
	if numExtensions > 0 {
		extensionsLength += 4 * numExtensions
		length += 2 + extensionsLength
	}

	x := make([]byte, 4+length)
	x[0] = HandshakeTypeClientHello
	x[1] = uint8(length >> 16)
	x[2] = uint8(length >> 8)
	x[3] = uint8(length)
	x[4] = uint8(m.version >> 8)
	x[5] = uint8(m.version)
	copy(x[6:38], m.random)
	x[38] = uint8(len(m.sessionId))
	copy(x[39:39+len(m.sessionId)], m.sessionId)

    xx := x[39+len(m.sessionId):]
    xx[0] = uint8(len(m.cookie))
    copy(xx[1:], m.cookie)

    y := xx[1+len(m.cookie):]
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
        z[0] = 0x00
        z[1] = 0x0f
        z[2] = 0x00
        z[3] = 0x01
		z[4] = m.heartbeat
	}

	m.raw = x

	return x
}
