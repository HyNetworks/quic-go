package handshake

import (
	"bytes"
	"math/rand/v2"
	"slices"
	"testing"

	utls "github.com/refraction-networking/utls"
	"github.com/stretchr/testify/require"
)

func TestEncodeTrustAnchorIDs(t *testing.T) {
	data := encodeTrustAnchorIDs(chromeTrustAnchorIDs)

	// a 16-bit length covering the rest, then 8-bit length-prefixed IDs
	require.GreaterOrEqual(t, len(data), 2)
	require.Equal(t, len(data)-2, int(data[0])<<8|int(data[1]))
	var ids [][]byte
	for rest := data[2:]; len(rest) > 0; {
		n := int(rest[0])
		require.NotZero(t, n)
		require.GreaterOrEqual(t, len(rest), 1+n)
		ids = append(ids, rest[1:1+n])
		rest = rest[1+n:]
	}
	require.ElementsMatch(t, chromeTrustAnchorIDs, ids)
	require.True(t, slices.IsSortedFunc(ids, bytes.Compare))

	// the order on the wire doesn't depend on the input order
	shuffled := slices.Clone(chromeTrustAnchorIDs)
	rand.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
	require.Equal(t, data, encodeTrustAnchorIDs(shuffled))
}

func TestChromeClientHelloSpecHasTrustAnchors(t *testing.T) {
	var found int
	for _, ext := range chromeQUICClientHelloSpec(nil).Extensions {
		if g, ok := ext.(*utls.GenericExtension); ok && g.Id == extensionTrustAnchors {
			found++
			require.Equal(t, chromeTrustAnchorsData, g.Data)
		}
	}
	require.Equal(t, 1, found)
}
