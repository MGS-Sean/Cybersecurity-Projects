// ©AngelaMos | 2026
// protocol.go

package mysql

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	packetHeaderSize    = 4
	protocolVersion     = 0x0a
	serverVersionString = "5.7.40-canary"

	capabilityFlagsLower = uint16(0xf7ff)
	capabilityFlagsUpper = uint16(0x81ff)

	characterSetUtf8MB4 = 0x21
	statusFlags         = uint16(0x0002)
	authPluginDataLen   = byte(0x15)

	authPluginName = "mysql_native_password"

	errPacketHeader      = 0xff
	errCodeAccessDenied  = uint16(1045)
	sqlStateMarker       = '#'
	sqlStateAccessDenied = "28000"

	seqIDServerHandshake byte = 0x00
	seqIDServerErr       byte = 0x02

	maxPacketSize             = 0x00ffffff
	handshakeResponseMaxBytes = 64 * 1024

	handshakeResponseFillerLen   = 23
	handshakeResponseHeaderBytes = 4 + 4 + 1 + handshakeResponseFillerLen

	authPluginDataTotalLen = 20
	authPluginDataPart1Len = 8
	authPluginDataPart2Len = 12
)

var (
	ErrShortPacket     = errors.New("mysql: short packet header")
	ErrPacketTooLarge  = errors.New("mysql: packet exceeds max size")
	ErrInvalidPayload  = errors.New("mysql: invalid payload structure")
	ErrUsernameMissing = errors.New(
		"mysql: username missing or unterminated",
	)
	ErrHTTPTriggerNotSupported = errors.New(
		"mysql: Trigger via HTTP is not applicable (use the TCP listener)",
	)
)

type ClientAuth struct {
	Capabilities  uint32
	MaxPacketSize uint32
	Charset       uint8
	Username      string
}

func BuildHandshakeV10(
	connID uint32,
	authData [authPluginDataTotalLen]byte,
) ([]byte, error) {
	var payload bytes.Buffer
	payload.WriteByte(protocolVersion)
	payload.WriteString(serverVersionString)
	payload.WriteByte(0x00)

	var connIDBytes [4]byte
	binary.LittleEndian.PutUint32(connIDBytes[:], connID)
	payload.Write(connIDBytes[:])

	payload.Write(authData[:authPluginDataPart1Len])
	payload.WriteByte(0x00)

	var capLower [2]byte
	binary.LittleEndian.PutUint16(capLower[:], capabilityFlagsLower)
	payload.Write(capLower[:])

	payload.WriteByte(characterSetUtf8MB4)

	var statusBytes [2]byte
	binary.LittleEndian.PutUint16(statusBytes[:], statusFlags)
	payload.Write(statusBytes[:])

	var capUpper [2]byte
	binary.LittleEndian.PutUint16(capUpper[:], capabilityFlagsUpper)
	payload.Write(capUpper[:])

	payload.WriteByte(authPluginDataLen)

	var reserved [10]byte
	payload.Write(reserved[:])

	payload.Write(authData[authPluginDataPart1Len:])
	payload.WriteByte(0x00)

	payload.WriteString(authPluginName)
	payload.WriteByte(0x00)

	return wrapPacket(payload.Bytes(), seqIDServerHandshake)
}

func ReadClientAuth(r io.Reader) (*ClientAuth, error) {
	payload, err := readPacket(r)
	if err != nil {
		return nil, err
	}
	if len(payload) < handshakeResponseHeaderBytes+1 {
		return nil, fmt.Errorf(
			"%w: have %d bytes, need at least %d",
			ErrInvalidPayload,
			len(payload),
			handshakeResponseHeaderBytes+1,
		)
	}

	auth := &ClientAuth{
		Capabilities:  binary.LittleEndian.Uint32(payload[0:4]),
		MaxPacketSize: binary.LittleEndian.Uint32(payload[4:8]),
		Charset:       payload[8],
	}

	usernameStart := handshakeResponseHeaderBytes
	rel := bytes.IndexByte(payload[usernameStart:], 0x00)
	if rel < 0 {
		return nil, ErrUsernameMissing
	}
	auth.Username = string(payload[usernameStart : usernameStart+rel])
	return auth, nil
}

func BuildAccessDeniedErr(username, sourceHost string) ([]byte, error) {
	msg := fmt.Sprintf(
		`Access denied for user '%s'@'%s' (using password: YES)`,
		username,
		sourceHost,
	)

	var payload bytes.Buffer
	payload.WriteByte(errPacketHeader)

	var code [2]byte
	binary.LittleEndian.PutUint16(code[:], errCodeAccessDenied)
	payload.Write(code[:])

	payload.WriteByte(sqlStateMarker)
	payload.WriteString(sqlStateAccessDenied)
	payload.WriteString(msg)

	return wrapPacket(payload.Bytes(), seqIDServerErr)
}

func wrapPacket(payload []byte, seqID byte) ([]byte, error) {
	if len(payload) > maxPacketSize {
		return nil, fmt.Errorf(
			"%w: payload %d > max %d",
			ErrPacketTooLarge,
			len(payload),
			maxPacketSize,
		)
	}
	out := make([]byte, packetHeaderSize+len(payload))
	n := len(payload)
	out[0] = byte(n & 0xff)
	out[1] = byte((n >> 8) & 0xff)
	out[2] = byte((n >> 16) & 0xff)
	out[3] = seqID
	copy(out[packetHeaderSize:], payload)
	return out, nil
}

func readPacket(r io.Reader) ([]byte, error) {
	var hdr [packetHeaderSize]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrShortPacket, err)
	}
	payloadLen := uint32(hdr[0]) |
		uint32(hdr[1])<<8 |
		uint32(hdr[2])<<16
	if payloadLen > handshakeResponseMaxBytes {
		return nil, fmt.Errorf(
			"%w: payload %d > limit %d",
			ErrPacketTooLarge,
			payloadLen,
			handshakeResponseMaxBytes,
		)
	}
	if payloadLen == 0 {
		return nil, nil
	}
	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, fmt.Errorf("mysql: read payload: %w", err)
	}
	return payload, nil
}

func NewRandomAuthData() ([authPluginDataTotalLen]byte, error) {
	var data [authPluginDataTotalLen]byte
	if _, err := rand.Read(data[:]); err != nil {
		return data, fmt.Errorf("mysql: random auth data: %w", err)
	}
	return data, nil
}

func NewRandomConnectionID() (uint32, error) {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, fmt.Errorf("mysql: random connection id: %w", err)
	}
	return binary.LittleEndian.Uint32(b[:]), nil
}
