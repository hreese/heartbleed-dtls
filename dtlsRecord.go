package heartbleed_dtls

import (
	"bytes"
)

type dtlsRecord struct {
	raw            []byte
	contentType    uint8
	version        uint16
	epoch          uint16
	sequenceNumber uint64 // uint48
	length         uint16
	dtlsBody       []byte
}

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
	m1, ok := i.(*dtlsRecord)
	if !ok {
		return false
	}

	return bytes.Equal(m.raw, m1.raw) &&
		m.contentType == m1.contentType &&
		m.version == m1.version &&
		m.epoch == m1.epoch &&
		m.sequenceNumber == m1.sequenceNumber &&
		m.length == m1.length &&
		bytes.Equal(m.dtlsBody, m1.dtlsBody)
}
