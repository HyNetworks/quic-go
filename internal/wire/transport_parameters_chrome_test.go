package wire

import (
	"encoding/binary"
	"strings"
	"testing"
	"time"

	"github.com/apernet/quic-go/internal/protocol"
	"github.com/apernet/quic-go/quicvarint"
	"github.com/stretchr/testify/require"
)

// chromeTestParams mirrors the values a Chrome-parroting client advertises.
func chromeTestParams() *TransportParameters {
	return &TransportParameters{
		MaxIdleTimeout:                 30 * time.Second,
		MaxUDPPayloadSize:              1472,
		InitialMaxData:                 15728640,
		InitialMaxStreamDataBidiLocal:  6291456,
		InitialMaxStreamDataBidiRemote: 6291456,
		InitialMaxStreamDataUni:        6291456,
		MaxBidiStreamNum:               100,
		MaxUniStreamNum:                103,
		InitialSourceConnectionID:      protocol.ConnectionID{},
		MaxDatagramFrameSize:           65536,
		ChromeFingerprint:              true,
	}
}

// parseParamIDs walks a marshalled transport parameter blob and returns the
// parameter ids in wire order, along with each one's value length.
func parseParamIDs(t *testing.T, b []byte) ([]uint64, map[uint64]uint64) {
	t.Helper()
	var ids []uint64
	lengths := make(map[uint64]uint64)
	r := b
	for len(r) > 0 {
		id, n, err := quicvarint.Parse(r)
		require.NoError(t, err)
		r = r[n:]
		l, n, err := quicvarint.Parse(r)
		require.NoError(t, err)
		r = r[n:]
		require.GreaterOrEqual(t, uint64(len(r)), l, "truncated parameter value")
		r = r[l:]
		ids = append(ids, id)
		lengths[id] = l
	}
	return ids, lengths
}

func TestChromeTransportParametersSet(t *testing.T) {
	ids, lengths := parseParamIDs(t, chromeTestParams().Marshal(protocol.PerspectiveClient))

	// The full parameter set and nothing else. The GREASE parameter has a random
	// id, so it is checked separately.
	expected := []uint64{
		0x01, // max_idle_timeout
		0x03, // max_udp_payload_size
		0x04, // initial_max_data
		0x05, // initial_max_stream_data_bidi_local
		0x06, // initial_max_stream_data_bidi_remote
		0x07, // initial_max_stream_data_uni
		0x08, // initial_max_streams_bidi
		0x09, // initial_max_streams_uni
		0x0f, // initial_source_connection_id
		0x11, // version_information
		0x20, // max_datagram_frame_size
		0x3128,
	}
	for _, id := range expected {
		require.Contains(t, ids, id, "missing parameter 0x%x", id)
	}
	require.Len(t, ids, len(expected)+1, "unexpected parameter count (expected Chrome's set plus one GREASE)")

	// Parameters that must never be sent; emitting one gives the game away.
	for _, id := range []uint64{
		0x0a, // ack_delay_exponent
		0x0b, // max_ack_delay
		0x0c, // disable_active_migration
		0x0e, // active_connection_id_limit
		0x1d, // reset_stream_at
	} {
		require.NotContains(t, ids, id, "parameter 0x%x should be absent", id)
	}

	// The source connection ID is zero-length.
	require.Zero(t, lengths[0x0f])
}

func TestChromeTransportParametersGREASE(t *testing.T) {
	ids, lengths := parseParamIDs(t, chromeTestParams().Marshal(protocol.PerspectiveClient))

	var greaseID uint64
	for _, id := range ids {
		if id > 0x3128 {
			greaseID = id
			break
		}
	}
	require.NotZero(t, greaseID, "no GREASE parameter found")

	// RFC 9000 section 18.1 reserves ids of the form 31*N+27.
	require.Equal(t, uint64(27), greaseID%31, "GREASE id must be 31*N+27")
	// The id must need a full 8-byte varint, unlike quic-go's short one.
	require.Equal(t, 8, quicvarint.Len(greaseID))
	require.LessOrEqual(t, lengths[greaseID], uint64(chromeGREASEMaxValueLen))
}

func TestChromeTransportParametersGREASEValueLengthVaries(t *testing.T) {
	// The GREASE value length is drawn uniformly. A fixed length would be a
	// per-connection exclusion whenever the imitated client picked another.
	seen := make(map[uint64]struct{})
	for range 300 {
		ids, lengths := parseParamIDs(t, chromeTestParams().Marshal(protocol.PerspectiveClient))
		for _, id := range ids {
			if id > 0x3128 {
				seen[lengths[id]] = struct{}{}
				break
			}
		}
	}
	// Far fewer distinct lengths than draws would mean the range is too narrow.
	require.Greater(t, len(seen), 12, "GREASE value length barely varies: %v", seen)
	for l := range seen {
		require.LessOrEqual(t, l, uint64(chromeGREASEMaxValueLen))
	}
}

func TestChromeTransportParametersVersionOrderIsShuffled(t *testing.T) {
	// The available-version list is shuffled; a fixed order is a tell.
	var v1First, greaseFirst int
	for range 200 {
		b := chromeTestParams().Marshal(protocol.PerspectiveClient)
		r := b
		for len(r) > 0 {
			id, n, err := quicvarint.Parse(r)
			require.NoError(t, err)
			r = r[n:]
			l, n, err := quicvarint.Parse(r)
			require.NoError(t, err)
			r = r[n:]
			if id == uint64(versionInformationParameterID) {
				if binary.BigEndian.Uint32(r[4:8]) == uint32(protocol.Version1) {
					v1First++
				} else {
					greaseFirst++
				}
				break
			}
			r = r[l:]
		}
	}
	require.Positive(t, v1First, "version 1 never leads the available list")
	require.Positive(t, greaseFirst, "the GREASE version never leads the available list")
}

func TestChromeTransportParametersVersionInformation(t *testing.T) {
	b := chromeTestParams().Marshal(protocol.PerspectiveClient)

	// Locate version_information and decode its value.
	r := b
	var val []byte
	for len(r) > 0 {
		id, n, err := quicvarint.Parse(r)
		require.NoError(t, err)
		r = r[n:]
		l, n, err := quicvarint.Parse(r)
		require.NoError(t, err)
		r = r[n:]
		if id == uint64(versionInformationParameterID) {
			val = r[:l]
			break
		}
		r = r[l:]
	}
	require.Len(t, val, 12, "chosen version plus two available versions")

	// Chosen version is always 1.
	require.Equal(t, uint32(protocol.Version1), binary.BigEndian.Uint32(val[0:4]))

	// The available list holds version 1 and one GREASE version in either order,
	// so identify them by value rather than position.
	first := binary.BigEndian.Uint32(val[4:8])
	second := binary.BigEndian.Uint32(val[8:12])
	var grease uint32
	switch {
	case first == uint32(protocol.Version1):
		grease = second
	case second == uint32(protocol.Version1):
		grease = first
	default:
		t.Fatalf("available versions %#x, %#x contain no version 1", first, second)
	}

	// RFC 9000 section 15 reserves versions matching 0x?a?a?a?a.
	for i := range 4 {
		v := byte(grease >> (8 * i))
		require.Equal(t, byte(0x0a), v&0x0f, "GREASE version byte %d low nibble", i)
	}
}

func TestChromeTransportParametersOrderIsShuffled(t *testing.T) {
	// The parameter order is permuted per connection; a fixed order is itself a
	// fingerprint. Repeated runs colliding on one order would be vanishingly
	// unlikely.
	seen := make(map[string]struct{})
	for range 30 {
		ids, _ := parseParamIDs(t, chromeTestParams().Marshal(protocol.PerspectiveClient))
		var key strings.Builder
		for _, id := range ids {
			// Normalize the random GREASE id so only its position matters.
			if id > 0x3128 {
				id = 0xffff
			}
			key.WriteString(string(rune(id)) + ",")
		}
		seen[key.String()] = struct{}{}
	}
	require.Greater(t, len(seen), 1, "parameter order is not being shuffled")
}

func TestChromeTransportParametersRoundTrip(t *testing.T) {
	// Whatever cosmetics we apply, the peer must still be able to parse our
	// parameters and read back the values we actually intend to honor.
	p := chromeTestParams()
	var parsed TransportParameters
	require.NoError(t, parsed.Unmarshal(p.Marshal(protocol.PerspectiveClient), protocol.PerspectiveClient))

	require.Equal(t, p.MaxIdleTimeout, parsed.MaxIdleTimeout)
	require.Equal(t, p.MaxUDPPayloadSize, parsed.MaxUDPPayloadSize)
	require.Equal(t, p.InitialMaxData, parsed.InitialMaxData)
	require.Equal(t, p.InitialMaxStreamDataBidiLocal, parsed.InitialMaxStreamDataBidiLocal)
	require.Equal(t, p.InitialMaxStreamDataBidiRemote, parsed.InitialMaxStreamDataBidiRemote)
	require.Equal(t, p.InitialMaxStreamDataUni, parsed.InitialMaxStreamDataUni)
	require.Equal(t, p.MaxBidiStreamNum, parsed.MaxBidiStreamNum)
	require.Equal(t, p.MaxUniStreamNum, parsed.MaxUniStreamNum)
	require.Equal(t, p.MaxDatagramFrameSize, parsed.MaxDatagramFrameSize)
	require.Equal(t, p.InitialSourceConnectionID, parsed.InitialSourceConnectionID)

	// The omitted parameters must come back as the protocol defaults.
	require.Equal(t, protocol.DefaultAckDelayExponent, int(parsed.AckDelayExponent))
	require.Equal(t, protocol.DefaultMaxAckDelay, parsed.MaxAckDelay)
	require.Equal(t, uint64(protocol.DefaultActiveConnectionIDLimit), parsed.ActiveConnectionIDLimit)
	require.False(t, parsed.DisableActiveMigration)
}
