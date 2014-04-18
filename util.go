package heartbleed_dtls

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"log"
	"os"
)

var logClientHello *log.Logger

func init() {
	logClientHello = log.New(os.Stdout, "[ClientHello] ", 0)
}

func VisuallyCompareByteArray(a, b []byte) (hda, hdb, hddiff, places string) {
	var smaller, larger []byte
	lenA := len(a)
	lenB := len(b)
	if lenA > lenB {
		smaller = b
		larger = a
	} else {
		smaller = a
		larger = b
	}

	dOffsets := make([]int, len(larger))
	numDiffs := 0
	var diffMap bytes.Buffer

	for i, _ := range smaller {
		if smaller[i] == larger[i] {
			diffMap.Write([]byte{0x00})
		} else {
			diffMap.Write([]byte{0x58})
			dOffsets[numDiffs] = i
			numDiffs += 1
		}
	}
	for _, _ = range larger[len(smaller):] {
		diffMap.Write([]byte{0x2a})
	}

	diffDetails := bytes.NewBufferString("Offset (hex/dec): Value a   | Values b\n")
	for _, v := range dOffsets[:numDiffs] {
		diffDetails.WriteString(fmt.Sprintf("0x%04x (%04d)   : 0x%02x (%02d) | 0x%02x (%02d)\n", v, v, a[v], a[v], b[v], b[v]))
	}

	return hex.Dump(a), hex.Dump(b), hex.Dump(diffMap.Bytes()), diffDetails.String()
}
