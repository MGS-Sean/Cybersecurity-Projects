// ©AngelaMos | 2026
// protocol_test.go

package mysql_test

import (
	"bytes"
	"encoding/binary"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/token/generators/mysql"
)

const (
	packetHeaderSize     = 4
	expectedProtoVersion = 0x0a
	expectedCharset      = 0x21
)

func buildHandshakeResponse41(t *testing.T, username string) []byte {
	t.Helper()
	var payload bytes.Buffer

	var caps [4]byte
	binary.LittleEndian.PutUint32(caps[:], 0x0001a285)
	payload.Write(caps[:])

	var maxPkt [4]byte
	binary.LittleEndian.PutUint32(maxPkt[:], 0x01000000)
	payload.Write(maxPkt[:])

	payload.WriteByte(expectedCharset)

	var filler [23]byte
	payload.Write(filler[:])

	payload.WriteString(username)
	payload.WriteByte(0x00)

	body := payload.Bytes()
	out := make([]byte, packetHeaderSize+len(body))
	n := len(body)
	out[0] = byte(n & 0xff)
	out[1] = byte((n >> 8) & 0xff)
	out[2] = byte((n >> 16) & 0xff)
	out[3] = 0x01
	copy(out[packetHeaderSize:], body)
	return out
}

func TestBuildHandshakeV10_HasCorrectPacketHeader(t *testing.T) {
	auth := [20]byte{
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
		11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
	}
	pkt, err := mysql.BuildHandshakeV10(0xdeadbeef, auth)
	require.NoError(t, err)
	require.Greater(t, len(pkt), packetHeaderSize)

	payloadLen := int(pkt[0]) |
		int(pkt[1])<<8 |
		int(pkt[2])<<16
	require.Equal(t, len(pkt)-packetHeaderSize, payloadLen)
	require.Equal(t, byte(0x00), pkt[3], "server handshake sequence ID is 0")
}

func TestBuildHandshakeV10_PayloadStartsWithProtocolVersion(t *testing.T) {
	var auth [20]byte
	pkt, err := mysql.BuildHandshakeV10(0x1234, auth)
	require.NoError(t, err)
	require.Equal(t, byte(expectedProtoVersion), pkt[packetHeaderSize])
}

func TestBuildHandshakeV10_ContainsServerVersionString(t *testing.T) {
	var auth [20]byte
	pkt, err := mysql.BuildHandshakeV10(0x1234, auth)
	require.NoError(t, err)
	require.Contains(
		t,
		string(pkt),
		"5.7.40-canary",
		"handshake must advertise the canary-server version string for verisimilitude",
	)
}

func TestBuildHandshakeV10_AdvertisesMySQLNativePassword(t *testing.T) {
	var auth [20]byte
	pkt, err := mysql.BuildHandshakeV10(0x1234, auth)
	require.NoError(t, err)
	require.Contains(t, string(pkt), "mysql_native_password")
}

func TestBuildHandshakeV10_EmbedsConnectionIDLittleEndian(t *testing.T) {
	var auth [20]byte
	connID := uint32(0xdeadbeef)
	pkt, err := mysql.BuildHandshakeV10(connID, auth)
	require.NoError(t, err)

	versionEnd := bytes.IndexByte(
		pkt[packetHeaderSize+1:],
		0x00,
	) + packetHeaderSize + 1
	require.Greater(t, versionEnd, packetHeaderSize+1)
	connIDStart := versionEnd + 1
	got := binary.LittleEndian.Uint32(pkt[connIDStart : connIDStart+4])
	require.Equal(t, connID, got)
}

func TestBuildHandshakeV10_EmbedsAuthDataInTwoParts(t *testing.T) {
	auth := [20]byte{
		10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
		20, 21, 22, 23, 24, 25, 26, 27, 28, 29,
	}
	pkt, err := mysql.BuildHandshakeV10(0xcafef00d, auth)
	require.NoError(t, err)
	require.Contains(
		t,
		string(pkt),
		string(auth[:8]),
		"first 8 bytes of auth data must appear in handshake",
	)
	require.Contains(
		t,
		string(pkt),
		string(auth[8:]),
		"last 12 bytes of auth data must appear in handshake (after part-1 + filler + caps + ...)",
	)
}

func TestReadClientAuth_ExtractsUsername(t *testing.T) {
	pkt := buildHandshakeResponse41(t, "canary_abc123def456")
	auth, err := mysql.ReadClientAuth(bytes.NewReader(pkt))
	require.NoError(t, err)
	require.NotNil(t, auth)
	require.Equal(t, "canary_abc123def456", auth.Username)
}

func TestReadClientAuth_CapturesCapabilities(t *testing.T) {
	pkt := buildHandshakeResponse41(t, "anyone")
	auth, err := mysql.ReadClientAuth(bytes.NewReader(pkt))
	require.NoError(t, err)
	require.Equal(t, uint32(0x0001a285), auth.Capabilities)
	require.Equal(t, uint32(0x01000000), auth.MaxPacketSize)
	require.Equal(t, uint8(expectedCharset), auth.Charset)
}

func TestReadClientAuth_EmptyUsernameStillParses(t *testing.T) {
	pkt := buildHandshakeResponse41(t, "")
	auth, err := mysql.ReadClientAuth(bytes.NewReader(pkt))
	require.NoError(t, err)
	require.Empty(t, auth.Username)
}

func TestReadClientAuth_ShortPayloadReturnsError(t *testing.T) {
	short := make([]byte, packetHeaderSize+5)
	short[0] = 0x05
	_, err := mysql.ReadClientAuth(bytes.NewReader(short))
	require.Error(t, err)
	require.ErrorIs(t, err, mysql.ErrInvalidPayload)
}

func TestReadClientAuth_NoUsernameTerminatorReturnsError(t *testing.T) {
	var payload bytes.Buffer
	var caps [4]byte
	payload.Write(caps[:])
	var maxPkt [4]byte
	payload.Write(maxPkt[:])
	payload.WriteByte(expectedCharset)
	var filler [23]byte
	payload.Write(filler[:])
	payload.WriteString("nocan_terminator_here_no_null")
	body := payload.Bytes()

	out := make([]byte, packetHeaderSize+len(body))
	n := len(body)
	out[0] = byte(n & 0xff)
	out[1] = byte((n >> 8) & 0xff)
	out[2] = byte((n >> 16) & 0xff)
	out[3] = 0x01
	copy(out[packetHeaderSize:], body)

	_, err := mysql.ReadClientAuth(bytes.NewReader(out))
	require.Error(t, err)
	require.ErrorIs(t, err, mysql.ErrUsernameMissing)
}

func TestReadClientAuth_EmptyReaderReturnsShortPacket(t *testing.T) {
	_, err := mysql.ReadClientAuth(bytes.NewReader(nil))
	require.Error(t, err)
	require.ErrorIs(t, err, mysql.ErrShortPacket)
}

func TestReadClientAuth_OversizePacketRejected(t *testing.T) {
	var hdr [packetHeaderSize]byte
	hdr[0] = 0x01
	hdr[1] = 0x00
	hdr[2] = 0x10
	hdr[3] = 0x01

	r := io.MultiReader(
		bytes.NewReader(hdr[:]),
		strings.NewReader(strings.Repeat("X", 70000)),
	)
	_, err := mysql.ReadClientAuth(r)
	require.Error(t, err)
	require.ErrorIs(t, err, mysql.ErrPacketTooLarge)
}

func TestBuildAccessDeniedErr_HasCorrectMarkerAndCode(t *testing.T) {
	pkt, err := mysql.BuildAccessDeniedErr("canary_xyz", "203.0.113.50")
	require.NoError(t, err)
	require.Greater(t, len(pkt), packetHeaderSize)

	require.Equal(
		t,
		byte(0xff),
		pkt[packetHeaderSize],
		"ERR packet header byte",
	)
	code := binary.LittleEndian.Uint16(
		pkt[packetHeaderSize+1 : packetHeaderSize+3],
	)
	require.Equal(
		t,
		uint16(1045),
		code,
		"MySQL error code 1045 (access denied)",
	)
}

func TestBuildAccessDeniedErr_HasSQLStateMarkerAnd28000(t *testing.T) {
	pkt, err := mysql.BuildAccessDeniedErr("canary_xyz", "203.0.113.50")
	require.NoError(t, err)
	require.Equal(
		t,
		byte('#'),
		pkt[packetHeaderSize+3],
		"SQL state marker must be '#'",
	)
	require.Equal(
		t,
		"28000",
		string(pkt[packetHeaderSize+4:packetHeaderSize+9]),
		"SQL state 28000 (invalid authorization)",
	)
}

func TestBuildAccessDeniedErr_MessageContainsUserAndHost(t *testing.T) {
	pkt, err := mysql.BuildAccessDeniedErr("canary_abc", "203.0.113.7")
	require.NoError(t, err)
	require.Contains(
		t,
		string(pkt),
		`Access denied for user 'canary_abc'@'203.0.113.7' (using password: YES)`,
	)
}

func TestBuildAccessDeniedErr_SequenceIDIs2(t *testing.T) {
	pkt, err := mysql.BuildAccessDeniedErr("u", "h")
	require.NoError(t, err)
	require.Equal(
		t,
		byte(0x02),
		pkt[3],
		"ERR packet sequence ID is 2 (after handshake=0 and client auth=1)",
	)
}

func TestRoundTrip_BuildAndParseUsername(t *testing.T) {
	cases := []string{
		"canary_abcdef0123",
		"canary_xyz",
		"root",
		"",
		"app_user",
	}
	for _, name := range cases {
		name := name
		t.Run("username="+name, func(t *testing.T) {
			pkt := buildHandshakeResponse41(t, name)
			auth, err := mysql.ReadClientAuth(bytes.NewReader(pkt))
			require.NoError(t, err)
			require.Equal(t, name, auth.Username)
		})
	}
}

func TestNewRandomAuthData_ReturnsTwentyBytes(t *testing.T) {
	d, err := mysql.NewRandomAuthData()
	require.NoError(t, err)
	require.Len(t, d, 20)
}

func TestNewRandomAuthData_DistinctCallsProduceDistinctOutputs(t *testing.T) {
	seen := make(map[[20]byte]struct{})
	for range 50 {
		d, err := mysql.NewRandomAuthData()
		require.NoError(t, err)
		seen[d] = struct{}{}
	}
	require.Greater(
		t,
		len(seen),
		45,
		"50 calls to NewRandomAuthData should produce near-50 unique values",
	)
}

func TestNewRandomConnectionID_DistinctCallsProduceDistinctOutputs(
	t *testing.T,
) {
	seen := make(map[uint32]struct{})
	for range 50 {
		id, err := mysql.NewRandomConnectionID()
		require.NoError(t, err)
		seen[id] = struct{}{}
	}
	require.Greater(t, len(seen), 45)
}

func TestErrors_AreDistinctSentinels(t *testing.T) {
	require.NotErrorIs(t, mysql.ErrShortPacket, mysql.ErrPacketTooLarge)
	require.NotErrorIs(t, mysql.ErrPacketTooLarge, mysql.ErrInvalidPayload)
	require.NotErrorIs(t, mysql.ErrInvalidPayload, mysql.ErrUsernameMissing)
}
