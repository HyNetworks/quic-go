package quic

import (
	"testing"

	"github.com/apernet/quic-go/internal/ackhandler"
	"github.com/apernet/quic-go/internal/handshake"
	"github.com/apernet/quic-go/internal/monotime"
	"github.com/apernet/quic-go/internal/protocol"
	"github.com/apernet/quic-go/internal/wire"
	"github.com/apernet/quic-go/quicvarint"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

// chaosTestPayload builds a payload holding one contiguous CRYPTO frame, which
// is what the Initial packet carrying a ClientHello looks like before chaos
// protection is applied.
func chaosTestPayload(dataLen int) payload {
	data := make([]byte, dataLen)
	for i := range data {
		data[i] = byte(i)
	}
	cf := &wire.CryptoFrame{Data: data}
	return payload{
		frames: []ackhandler.Frame{{Frame: cf, Handler: emptyHandler{}}},
		length: cf.Length(protocol.Version1),
	}
}

// parseChaosPayload decodes an assembled payload back into CRYPTO frames, a PING
// count and a padding byte count.
//
// A chaos-protected Initial payload only ever contains PADDING (0x00), PING
// (0x01) and CRYPTO (0x06), so this walks those three directly rather than
// going through wire.FrameParser, whose ParseType silently skips padding.
func parseChaosPayload(t *testing.T, raw []byte) (crypto []*wire.CryptoFrame, pings, padding int) {
	t.Helper()
	for len(raw) > 0 {
		switch raw[0] {
		case 0x00: // PADDING
			padding++
			raw = raw[1:]
		case 0x01: // PING
			pings++
			raw = raw[1:]
		case 0x06: // CRYPTO
			raw = raw[1:]
			offset, n, err := quicvarint.Parse(raw)
			require.NoError(t, err)
			raw = raw[n:]
			length, n, err := quicvarint.Parse(raw)
			require.NoError(t, err)
			raw = raw[n:]
			require.GreaterOrEqual(t, uint64(len(raw)), length, "truncated CRYPTO frame")
			crypto = append(crypto, &wire.CryptoFrame{
				Offset: protocol.ByteCount(offset),
				Data:   raw[:length],
			})
			raw = raw[length:]
		default:
			t.Fatalf("unexpected frame type 0x%x in chaos-protected payload", raw[0])
		}
	}
	return crypto, pings, padding
}

func TestChaosProtectionShreddsCryptoFrame(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	tp := newTestPacketPacker(t, mockCtrl, protocol.PerspectiveClient, true)

	const dataLen = 1000
	const paddingLen = 200
	pl := chaosTestPayload(dataLen)

	raw, err := tp.packer.appendChaosProtectedPayload(nil, pl, paddingLen, protocol.Version1)
	require.NoError(t, err)

	// The whole point: same size in, same size out.
	require.Len(t, raw, int(pl.length+paddingLen))

	crypto, pings, padding := parseChaosPayload(t, raw)

	// A single frame would mean we did nothing. With no unsplittable frames in
	// the way and padding to spare, every attempt lands, so the count is one
	// more than the number of attempts.
	require.GreaterOrEqual(t, len(crypto), 1+chaosMinAddedCryptoFrames)
	require.LessOrEqual(t, len(crypto), 1+chaosMaxAddedCryptoFrames)
	require.GreaterOrEqual(t, pings, chaosMinPingFrames)
	require.LessOrEqual(t, pings, chaosMaxPingFrames)
	require.Positive(t, padding)

	// The CRYPTO fragments must tile the original data exactly once, with no
	// gaps and no overlaps, or the peer can't reassemble the ClientHello.
	reassembled := make([]byte, dataLen)
	covered := make([]bool, dataLen)
	for _, cf := range crypto {
		for i, b := range cf.Data {
			off := int(cf.Offset) + i
			require.Less(t, off, dataLen, "fragment runs past the end of the data")
			require.False(t, covered[off], "byte %d covered twice", off)
			covered[off] = true
			reassembled[off] = b
		}
	}
	for i, c := range covered {
		require.True(t, c, "byte %d not covered by any fragment", i)
	}
	for i := range reassembled {
		require.Equal(t, byte(i), reassembled[i])
	}
}

func TestChaosProtectionShufflesOffsets(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	tp := newTestPacketPacker(t, mockCtrl, protocol.PerspectiveClient, true)

	// CRYPTO offsets must arrive out of order; always-ascending would itself be
	// the fingerprint.
	var sawOutOfOrder bool
	for range 20 {
		raw, err := tp.packer.appendChaosProtectedPayload(nil, chaosTestPayload(1000), 200, protocol.Version1)
		require.NoError(t, err)
		crypto, _, _ := parseChaosPayload(t, raw)
		for i := 1; i < len(crypto); i++ {
			if crypto[i].Offset < crypto[i-1].Offset {
				sawOutOfOrder = true
			}
		}
		if sawOutOfOrder {
			break
		}
	}
	require.True(t, sawOutOfOrder, "CRYPTO frame offsets are never shuffled")
}

func TestChaosProtectionTinyPaddingBudget(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	tp := newTestPacketPacker(t, mockCtrl, protocol.PerspectiveClient, true)

	// With no padding to spend there's no room for extra frame headers, so we
	// must fall back to emitting the data unsplit rather than overrun the packet.
	for _, paddingLen := range []protocol.ByteCount{0, 1, 2, 5} {
		pl := chaosTestPayload(500)
		raw, err := tp.packer.appendChaosProtectedPayload(nil, pl, paddingLen, protocol.Version1)
		require.NoError(t, err, "padding budget %d", paddingLen)
		require.Len(t, raw, int(pl.length+paddingLen), "padding budget %d", paddingLen)

		crypto, _, _ := parseChaosPayload(t, raw)
		total := 0
		for _, cf := range crypto {
			total += len(cf.Data)
		}
		require.Equal(t, 500, total, "data lost with padding budget %d", paddingLen)
	}
}

func TestChaosProtectionPreservesOtherFrames(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	tp := newTestPacketPacker(t, mockCtrl, protocol.PerspectiveClient, true)

	// Non-CRYPTO frames can't be split, but they must still survive the shuffle.
	pl := chaosTestPayload(400)
	ping := &wire.PingFrame{}
	pl.frames = append(pl.frames, ackhandler.Frame{Frame: ping, Handler: emptyHandler{}})
	pl.length += ping.Length(protocol.Version1)

	raw, err := tp.packer.appendChaosProtectedPayload(nil, pl, 100, protocol.Version1)
	require.NoError(t, err)
	require.Len(t, raw, int(pl.length+100))

	crypto, pings, _ := parseChaosPayload(t, raw)
	total := 0
	for _, cf := range crypto {
		total += len(cf.Data)
	}
	require.Equal(t, 400, total)
	// The carried PING plus the chaos PINGs.
	require.GreaterOrEqual(t, pings, chaosMinPingFrames+1)
}

// available is what's left of a 1250-byte Initial after the long header.
const chaosTestAvailable = 1220

func TestChromeCryptoSplitSinglePacket(t *testing.T) {
	zero := func(int) int { return 0 }
	// Data that fits in one packet is not split at all.
	first, last := chromeCryptoSplit(200, 0, chaosTestAvailable, zero)
	require.Zero(t, first)
	require.Zero(t, last)

	first, last = chromeCryptoSplit(0, 0, chaosTestAvailable, zero)
	require.Zero(t, first)
	require.Zero(t, last)

	// A packet with no room for two frames can't carry head and tail.
	first, last = chromeCryptoSplit(1000, 0, 4, zero)
	require.Zero(t, first)
	require.Zero(t, last)
}

func TestChromeCryptoSplitCarriesHeadAndTail(t *testing.T) {
	for _, pending := range []protocol.ByteCount{1650, 1700, 1750, 1800, 1850, 2500} {
		for r := range chaosFirstFrameLenRandom {
			first, last := chromeCryptoSplit(pending, 0, chaosTestAvailable, func(int) int { return r })
			require.Positive(t, first, "pending=%d r=%d", pending, r)
			require.Positive(t, last, "pending=%d r=%d", pending, r)

			// The leading frame covers the fixed part of the ClientHello, with
			// the randomized offset applied on top.
			require.Equal(t, protocol.ByteCount(chaosMinFirstFrameLen+r), first)

			// Head and tail plus their headers have to fit in one packet.
			total := first + last +
				cryptoFrameHeaderLen(0, first) +
				cryptoFrameHeaderLen(pending-last, last)
			require.LessOrEqual(t, total, protocol.ByteCount(chaosTestAvailable),
				"pending=%d r=%d: first packet overfull", pending, r)

			// Something must be left for the later packets, or nothing is deferred.
			require.Positive(t, pending-first-last, "pending=%d r=%d", pending, r)
		}
	}
}

func TestChromeCryptoSplitCoversAllData(t *testing.T) {
	// Head, tail and the deferred middle must tile the ClientHello exactly:
	// a gap stalls the handshake, an overlap is a protocol violation.
	for _, pending := range []protocol.ByteCount{1650, 1750, 1850, 2500, 3600} {
		first, last := chromeCryptoSplit(pending, 0, chaosTestAvailable, func(n int) int { return n / 2 })
		require.Positive(t, first, "pending=%d", pending)
		require.Positive(t, last, "pending=%d", pending)

		covered := make([]bool, pending)
		mark := func(off, n protocol.ByteCount) {
			for i := off; i < off+n; i++ {
				require.False(t, covered[i], "pending=%d: byte %d sent twice", pending, i)
				covered[i] = true
			}
		}
		mark(0, first)                  // head, first packet
		mark(pending-last, last)        // tail, first packet
		mark(first, pending-last-first) // middle, later packets
		for i, c := range covered {
			require.True(t, c, "pending=%d: byte %d never sent", pending, i)
		}
	}
}

func TestChromeCryptoSplitFirstInitialCarriesHeadAndTail(t *testing.T) {
	const maxPacketSize protocol.ByteCount = 1250
	mockCtrl := gomock.NewController(t)
	tp := newTestPacketPacker(t, mockCtrl, protocol.PerspectiveClient, true)
	now := monotime.Now()

	// A ClientHello too large for one Initial, as a post-quantum key share makes it.
	const helloLen = 1700
	hello := make([]byte, helloLen)
	for i := range hello {
		hello[i] = byte(i)
	}
	tp.initialStream.Write(hello)

	tp.pnManager.EXPECT().PeekPacketNumber(protocol.EncryptionInitial).
		Return(protocol.PacketNumber(1), protocol.PacketNumberLen1)
	tp.ackFramer.EXPECT().GetAckFrame(protocol.EncryptionInitial, now, gomock.Any())
	// Withholding the Initial ACK is conditional on Handshake keys existing,
	// which they do not this early.
	tp.sealingManager.EXPECT().GetHandshakeSealer().
		Return(nil, handshake.ErrKeysNotYetAvailable).AnyTimes()

	_, pl := tp.packer.maybeGetCryptoPacket(maxPacketSize, protocol.EncryptionInitial, now, false, false, protocol.Version1)

	var crypto []*wire.CryptoFrame
	for _, f := range pl.frames {
		if cf, ok := f.Frame.(*wire.CryptoFrame); ok {
			crypto = append(crypto, cf)
		}
	}
	require.Len(t, crypto, 2, "the first Initial must carry two CRYPTO frames")

	head, tail := crypto[0], crypto[1]
	require.Zero(t, head.Offset, "the first frame must start at the beginning")
	require.GreaterOrEqual(t, len(head.Data), chaosMinFirstFrameLen)
	require.Less(t, len(head.Data), chaosMinFirstFrameLen+chaosFirstFrameLenRandom)

	// The second frame must reach the very end of the ClientHello, and start
	// beyond where the first one stopped: the middle is deferred to a later
	// packet, so this one cannot be parsed on its own.
	require.Equal(t, protocol.ByteCount(helloLen), tail.Offset+protocol.ByteCount(len(tail.Data)))
	require.Greater(t, tail.Offset, head.Offset+protocol.ByteCount(len(head.Data)))
}
