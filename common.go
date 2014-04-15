package heartbleed_dtls

const (
	RecordTypeChangeCypherSpec uint8 = 20
	RecordTypeAlert            uint8 = 21
	RecordTypeHandshake        uint8 = 22
	RecordTypeApplicationData  uint8 = 23
)

const (
	VersionDTLS10 uint16 = 0xfeff
	VersionDTLS12 uint16 = 0xfefd
)

const (
	HandshakeTypeHelloRequest       uint8 = 0
	HandshakeTypeClientHello        uint8 = 1
	HandshakeTypeServerHello        uint8 = 2
	HandshakeTypeHelloVerifyRequest uint8 = 3
	HandshakeTypeCertificate        uint8 = 11
	HandshakeTypeServerKeyExchange  uint8 = 12
	HandshakeTypeCertificateRequest uint8 = 13
	HandshakeTypeServerHelloDone    uint8 = 14
	HandshakeTypeCertificateVerify  uint8 = 15
	HandshakeTypeClientKeyExchange  uint8 = 16
	HandshakeTypeFinished           uint8 = 20
)

const (
	extensionServerName          uint16 = 0
	extensionStatusRequest       uint16 = 5
	extensionSupportedCurves     uint16 = 10
	extensionSupportedPoints     uint16 = 11
	extensionSignatureAlgorithms uint16 = 13
    extensionHeartbeat           uint16 = 16
	extensionSessionTicket       uint16 = 35
    extensionRenegotiation       uint16 = 0xff01
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


