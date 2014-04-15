package heartbleed_dtls

const (
	TypeChangeCypherSpec uint8 = 20
	TypeAlert            uint8 = 21
	TypeHandshake        uint8 = 22
	TypeApplicationData  uint8 = 23
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

type dtlsRecord struct {
	raw            []byte
	contentType    uint8
	version        uint16
	epoch          uint16
	sequenceNumber uint64 // uint48
	length         uint16
	dtlsBody       []byte
}

type dtlsHandshake struct {
	raw             []byte
	handshakeType   uint8
	length          uint32 // uint24
	messageSequence uint16
	fragmentOffset  uint32
	fragmentLength  uint32
	body            []byte
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

var dtlsMinimalRecord = dtlsRecord{
	contentType:    TypeHandshake,
	version:        VersionDTLS10,
	epoch:          0,
	sequenceNumber: 0,
}

var dtlsMinimalHandshake = dtlsHandshake{
	raw:           nil,
	handshakeType: HandshakeTypeClientHello,
}

var dtlsMinimalClientHelloMsg = dtlsClientHelloMsg{
	raw:     nil,
	version: VersionDTLS10,
	random: []byte{0xd0, 0xdc, 0x8d, 0xd8, 0x9c, 0x6, 0xcc, 0x32, 0x8f, 0xcd,
		0x28, 0x3b, 0xea, 0xe9, 0x3d, 0xf3, 0x4d, 0xed, 0x67, 0xbe, 0xb4,
		0x5d, 0xdc, 0xb8, 0x45, 0xdd, 0x55, 0x1b, 0xf9, 0x9c, 0x3a, 0x80},
	sessionId:          nil,
	cookie:             nil,
	cipherSuites:       []uint16{0x0013}, // TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA is mandatory for TLS compliance
	compressionMethods: []uint8{0x00},
	ocspStapling:       false,
	serverName:         "",
	supportedCurves:    nil,
	supportedPoints:    nil,
	ticketSupported:    false,
	heartbeat:          0x01,
}
