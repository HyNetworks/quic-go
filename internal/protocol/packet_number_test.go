package protocol

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestInvalidPacketNumberIsSmallerThanAllValidPacketNumbers(t *testing.T) {
	require.Less(t, InvalidPacketNumber, PacketNumber(0))
}

func TestPacketNumberLenHasCorrectValue(t *testing.T) {
	require.EqualValues(t, 1, PacketNumberLen1)
	require.EqualValues(t, 2, PacketNumberLen2)
	require.EqualValues(t, 3, PacketNumberLen3)
	require.EqualValues(t, 4, PacketNumberLen4)
}

func TestDecodePacketNumber(t *testing.T) {
	require.Equal(t, PacketNumber(255), DecodePacketNumber(PacketNumberLen1, 10, 255))
	require.Equal(t, PacketNumber(0), DecodePacketNumber(PacketNumberLen1, 10, 0))
	require.Equal(t, PacketNumber(256), DecodePacketNumber(PacketNumberLen1, 127, 0))
	require.Equal(t, PacketNumber(256), DecodePacketNumber(PacketNumberLen1, 128, 0))
	require.Equal(t, PacketNumber(256), DecodePacketNumber(PacketNumberLen1, 256+126, 0))
	require.Equal(t, PacketNumber(512), DecodePacketNumber(PacketNumberLen1, 256+127, 0))
	require.Equal(t, PacketNumber(0xffff), DecodePacketNumber(PacketNumberLen2, 0xffff, 0xffff))
	require.Equal(t, PacketNumber(0xffff), DecodePacketNumber(PacketNumberLen2, 0xffff+1, 0xffff))

	// example from https://www.rfc-editor.org/rfc/rfc9000.html#section-a.3
	require.Equal(t, PacketNumber(0xa82f9b32), DecodePacketNumber(PacketNumberLen2, 0xa82f30ea, 0x9b32))
}

func TestPacketNumberLengthForHeader(t *testing.T) {
	require.Equal(t, PacketNumberLen2, PacketNumberLengthForHeader(1, InvalidPacketNumber))
	require.Equal(t, PacketNumberLen2, PacketNumberLengthForHeader(1<<15-2, InvalidPacketNumber))
	require.Equal(t, PacketNumberLen3, PacketNumberLengthForHeader(1<<15-1, InvalidPacketNumber))
	require.Equal(t, PacketNumberLen3, PacketNumberLengthForHeader(1<<23-2, InvalidPacketNumber))
	require.Equal(t, PacketNumberLen4, PacketNumberLengthForHeader(1<<23-1, InvalidPacketNumber))
	require.Equal(t, PacketNumberLen2, PacketNumberLengthForHeader(1<<15+9, 10))
	require.Equal(t, PacketNumberLen3, PacketNumberLengthForHeader(1<<15+10, 10))
	require.Equal(t, PacketNumberLen3, PacketNumberLengthForHeader(1<<23+99, 100))
	require.Equal(t, PacketNumberLen4, PacketNumberLengthForHeader(1<<23+100, 100))
	// examples from https://www.rfc-editor.org/rfc/rfc9000.html#section-a.2
	require.Equal(t, PacketNumberLen2, PacketNumberLengthForHeader(0xac5c02, 0xabe8b3))
	require.Equal(t, PacketNumberLen3, PacketNumberLengthForHeader(0xace8fe, 0xabe8b3))
}

func TestPacketNumberLengthForHeaderChrome(t *testing.T) {
	// quic-go's floor is 2 bytes; the parroted client uses 1 wherever the rule
	// allows, so every packet would otherwise be one byte longer.
	require.Equal(t, PacketNumberLen2, PacketNumberLengthForHeader(1, InvalidPacketNumber))
	require.Equal(t, PacketNumberLen1, PacketNumberLengthForHeaderChrome(1, InvalidPacketNumber, 0))

	// The threshold is on four times the larger of the unacked range and the
	// congestion window in packets. Pin both sides of each boundary.
	require.Equal(t, PacketNumberLen1, PacketNumberLengthForHeaderChrome(63, 0, 0))
	require.Equal(t, PacketNumberLen2, PacketNumberLengthForHeaderChrome(64, 0, 0))
	require.Equal(t, PacketNumberLen2, PacketNumberLengthForHeaderChrome(1<<14-1, 0, 0))
	require.Equal(t, PacketNumberLen4, PacketNumberLengthForHeaderChrome(1<<14, 0, 0))

	// The congestion window is a floor, so a wide-open window forces a longer
	// packet number even when everything is acknowledged.
	require.Equal(t, PacketNumberLen1, PacketNumberLengthForHeaderChrome(1000, 999, 63))
	require.Equal(t, PacketNumberLen2, PacketNumberLengthForHeaderChrome(1000, 999, 64))

	// The initial congestion window must still leave room for 1 byte, otherwise
	// the whole handshake is a byte wider than the client being imitated.
	require.Equal(t, PacketNumberLen1, PacketNumberLengthForHeaderChrome(1, InvalidPacketNumber, 32))

	// Three-byte packet numbers are never produced, though the default does
	// produce them; a lone 3-byte packet number would be a giveaway.
	require.Equal(t, PacketNumberLen3, PacketNumberLengthForHeader(1<<15+10, 10))
	for _, cwnd := range []PacketNumber{0, 32, 1000, 1 << 20} {
		for _, pn := range []PacketNumber{1, 63, 64, 1 << 10, 1<<14 - 1, 1 << 14, 1 << 20, 1 << 25} {
			require.NotEqual(t, PacketNumberLen3,
				PacketNumberLengthForHeaderChrome(pn, InvalidPacketNumber, cwnd),
				"pn=%d cwnd=%d", pn, cwnd)
		}
	}
}
