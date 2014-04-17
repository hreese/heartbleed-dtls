package heartbleed_dtls

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"testing"
)

// Test 1: simple package, empty body
func TestRecordConstruction1(t *testing.T) {
	r1 := dtlsRecord{
		raw:         nil,
		contentType: HandshakeTypeClientHello,
		version:     VersionDTLS12,
		dtlsBody:    nil,
	}

	// check if a record is equal to itself
	if !r1.equal(&r1) {
		t.Errorf("r1 not equal to itself")
	}

	// reference binary record
	r1_bref := []byte{
		0x01,
		0xfe, 0xfd,
		0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00,
	}
	r1b := r1.marshal()
	if !bytes.Equal(r1_bref, r1b) {
		t.Errorf("Error in dtlsRecord.marshal()")
		fmt.Println(hex.Dump(r1_bref))
		fmt.Println(hex.Dump(r1b))
	}

	r1_um := new(dtlsRecord)
	if !r1_um.unmarshal(r1b) {
		t.Errorf("Unable to dtlsRecord.marshal() r1b")
	}

	if r1.equal(r1_um) != true {
		t.Errorf("record.marshal().unmarshal is not equal() to record")
		fmt.Printf("r1:\n%+v\n", r1)
		fmt.Printf("r1_um:\n%+v\n", r1_um)
	}
}

// Test 2: random body, nonempty fields when possible
func TestRecordConstruction2(t *testing.T) {
	body := make([]byte, 512)
	_, err := rand.Read(body)
	if err != nil {
		t.Errorf("Unable to Read() from crypto/rand.")
	}

	r2 := dtlsRecord{
		raw:            nil,
		contentType:    HandshakeTypeFinished,
		version:        VersionDTLS10,
		epoch:          0xabcd,
		sequenceNumber: 0x00001234567890ab,
		length:         0,
		dtlsBody:       body,
	}

	// reference binary record
	r2_bref := make([]byte, 13+512)
	r2_bref_header := []byte{
		0x14,
		0xfe, 0xff,
		0xab, 0xcd,
		0x12, 0x34, 0x56, 0x78, 0x90, 0xab,
		0x02, 0x00,
	}
	copy(r2_bref[0:], r2_bref_header)
	copy(r2_bref[13:], body)

	r2b := r2.marshal()
	if !bytes.Equal(r2_bref, r2b) {
		t.Errorf("Error in dtlsRecord.marshal()")
		fmt.Print("packet:\n", hex.Dump(r2b))
		fmt.Print("reference:\n", hex.Dump(r2_bref))
	}

	// marshaling a packet twice should yield the same result (caching)
	r2b_again := r2.marshal()
	if !bytes.Equal(r2_bref, r2b_again) {
		t.Errorf("Error in dtlsRecord.marshal() when dtlsRecord was already marshalled")
		fmt.Print("packet:\n", hex.Dump(r2b))
		fmt.Print("reference:\n", hex.Dump(r2_bref))
	}
}
