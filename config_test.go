package quic

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/apernet/quic-go/internal/protocol"
	"github.com/apernet/quic-go/qlogwriter"
	"github.com/apernet/quic-go/quicvarint"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfigValidation(t *testing.T) {
	t.Run("nil config", func(t *testing.T) {
		require.NoError(t, validateConfig(nil))
	})

	t.Run("config with a few values set", func(t *testing.T) {
		conf := populateConfig(&Config{
			MaxIncomingStreams:     5,
			MaxStreamReceiveWindow: 10,
		})
		require.NoError(t, validateConfig(conf))
		require.Equal(t, int64(5), conf.MaxIncomingStreams)
		require.Equal(t, uint64(10), conf.MaxStreamReceiveWindow)
	})

	t.Run("stream limits", func(t *testing.T) {
		conf := &Config{
			MaxIncomingStreams:    1<<60 + 1,
			MaxIncomingUniStreams: 1<<60 + 2,
		}
		require.NoError(t, validateConfig(conf))
		require.Equal(t, int64(1<<60), conf.MaxIncomingStreams)
		require.Equal(t, int64(1<<60), conf.MaxIncomingUniStreams)
	})

	t.Run("flow control windows", func(t *testing.T) {
		conf := &Config{
			MaxStreamReceiveWindow:     quicvarint.Max + 1,
			MaxConnectionReceiveWindow: quicvarint.Max + 2,
		}
		require.NoError(t, validateConfig(conf))
		require.Equal(t, uint64(quicvarint.Max), conf.MaxStreamReceiveWindow)
		require.Equal(t, uint64(quicvarint.Max), conf.MaxConnectionReceiveWindow)
	})

	t.Run("initial packet size", func(t *testing.T) {
		// not set
		conf := &Config{InitialPacketSize: 0}
		require.NoError(t, validateConfig(conf))
		require.Zero(t, conf.InitialPacketSize)

		// too small
		conf = &Config{InitialPacketSize: 10}
		require.NoError(t, validateConfig(conf))
		require.Equal(t, uint16(1200), conf.InitialPacketSize)

		// too large
		conf = &Config{InitialPacketSize: protocol.MaxPacketBufferSize + 1}
		require.NoError(t, validateConfig(conf))
		require.Equal(t, uint16(protocol.MaxPacketBufferSize), conf.InitialPacketSize)
	})
}

func TestConfigHandshakeIdleTimeout(t *testing.T) {
	c := &Config{HandshakeIdleTimeout: time.Second * 11 / 2}
	require.Equal(t, 11*time.Second, c.handshakeTimeout())
}

// chromeParrot is set separately because, unlike every other field here, it
// deliberately overrides other values in populateConfig. Callers that assert
// populateConfig is idempotent must leave it off.
func configWithNonZeroNonFunctionFields(t *testing.T, chromeParrot bool) *Config {
	t.Helper()
	c := &Config{}
	v := reflect.ValueOf(c).Elem()

	typ := v.Type()
	for i := 0; i < typ.NumField(); i++ {
		f := v.Field(i)
		if !f.CanSet() {
			// unexported field; not cloned.
			continue
		}

		switch fn := typ.Field(i).Name; fn {
		case "GetConfigForClient", "RequireAddressValidation", "GetLogWriter", "AllowConnectionWindowIncrease", "Tracer":
			// Can't compare functions.
		case "Versions":
			f.Set(reflect.ValueOf([]Version{1, 2, 3}))
		case "ConnectionIDLength":
			f.Set(reflect.ValueOf(8))
		case "ConnectionIDGenerator":
			f.Set(reflect.ValueOf(&protocol.DefaultConnectionIDGenerator{ConnLen: protocol.DefaultConnectionIDLength}))
		case "HandshakeIdleTimeout":
			f.Set(reflect.ValueOf(time.Second))
		case "MaxIdleTimeout":
			f.Set(reflect.ValueOf(time.Hour))
		case "TokenStore":
			f.Set(reflect.ValueOf(NewLRUTokenStore(2, 3)))
		case "InitialStreamReceiveWindow":
			f.Set(reflect.ValueOf(uint64(1234)))
		case "MaxStreamReceiveWindow":
			f.Set(reflect.ValueOf(uint64(9)))
		case "InitialConnectionReceiveWindow":
			f.Set(reflect.ValueOf(uint64(4321)))
		case "MaxConnectionReceiveWindow":
			f.Set(reflect.ValueOf(uint64(10)))
		case "MaxIncomingStreams":
			f.Set(reflect.ValueOf(int64(11)))
		case "MaxIncomingUniStreams":
			f.Set(reflect.ValueOf(int64(12)))
		case "StatelessResetKey":
			f.Set(reflect.ValueOf(&StatelessResetKey{1, 2, 3, 4}))
		case "KeepAlivePeriod":
			f.Set(reflect.ValueOf(time.Second))
		case "EnableDatagrams":
			f.Set(reflect.ValueOf(true))
		case "OmitMaxDatagramFrameSize":
			f.Set(reflect.ValueOf(true))
		case "AssumePeerMaxDatagramFrameSize":
			f.Set(reflect.ValueOf(int64(1337)))
		case "MaxDatagramFrameSize":
			f.Set(reflect.ValueOf(int64(1200)))
		case "DisablePathManager":
			f.Set(reflect.ValueOf(true))
		case "DisableVersionNegotiationPackets":
			f.Set(reflect.ValueOf(true))
		case "InitialPacketSize":
			f.Set(reflect.ValueOf(uint16(1350)))
		case "DisablePathMTUDiscovery":
			f.Set(reflect.ValueOf(true))
		case "Allow0RTT":
			f.Set(reflect.ValueOf(true))
		case "EnableStreamResetPartialDelivery":
			f.Set(reflect.ValueOf(true))
		case "ChromeParrot":
			f.Set(reflect.ValueOf(chromeParrot))
		default:
			t.Fatalf("all fields must be accounted for, but saw unknown field %q", fn)
		}
	}
	return c
}

func TestConfigClone(t *testing.T) {
	t.Run("function fields", func(t *testing.T) {
		var calledAllowConnectionWindowIncrease, calledTracer bool
		c1 := &Config{
			GetConfigForClient:            func(info *ClientInfo) (*Config, error) { return nil, assert.AnError },
			AllowConnectionWindowIncrease: func(*Conn, uint64) bool { calledAllowConnectionWindowIncrease = true; return true },
			Tracer: func(context.Context, bool, ConnectionID) qlogwriter.Trace {
				calledTracer = true
				return nil
			},
		}
		c2 := c1.Clone()
		c2.AllowConnectionWindowIncrease(nil, 1234)
		require.True(t, calledAllowConnectionWindowIncrease)
		_, err := c2.GetConfigForClient(&ClientInfo{})
		require.ErrorIs(t, err, assert.AnError)
		c2.Tracer(context.Background(), true, protocol.ConnectionID{})
		require.True(t, calledTracer)
	})

	t.Run("non-function fields", func(t *testing.T) {
		c := configWithNonZeroNonFunctionFields(t, true)
		require.Equal(t, c, c.Clone())
	})

	t.Run("returns a copy", func(t *testing.T) {
		c1 := &Config{MaxIncomingStreams: 100}
		c2 := c1.Clone()
		require.NotNil(t, c2)
		require.NotSame(t, c1, c2)
	})
}

func TestConfigDefaultValues(t *testing.T) {
	// if set, the values should be copied
	c := configWithNonZeroNonFunctionFields(t, false)
	require.Equal(t, c, populateConfig(c))

	// if not set, some fields use default values
	c = populateConfig(&Config{})
	require.Equal(t, protocol.SupportedVersions, c.Versions)
	require.Equal(t, protocol.DefaultHandshakeIdleTimeout, c.HandshakeIdleTimeout)
	require.Equal(t, protocol.DefaultIdleTimeout, c.MaxIdleTimeout)
	require.EqualValues(t, protocol.DefaultInitialMaxStreamData, c.InitialStreamReceiveWindow)
	require.EqualValues(t, protocol.DefaultMaxReceiveStreamFlowControlWindow, c.MaxStreamReceiveWindow)
	require.EqualValues(t, protocol.DefaultInitialMaxData, c.InitialConnectionReceiveWindow)
	require.EqualValues(t, protocol.DefaultMaxReceiveConnectionFlowControlWindow, c.MaxConnectionReceiveWindow)
	require.EqualValues(t, protocol.DefaultMaxIncomingStreams, c.MaxIncomingStreams)
	require.EqualValues(t, protocol.DefaultMaxIncomingUniStreams, c.MaxIncomingUniStreams)
	require.False(t, c.DisablePathMTUDiscovery)
	require.Nil(t, c.GetConfigForClient)
}

func TestConfigZeroLimits(t *testing.T) {
	config := &Config{
		MaxIncomingStreams:    -1,
		MaxIncomingUniStreams: -1,
	}
	c := populateConfig(config)
	require.Zero(t, c.MaxIncomingStreams)
	require.Zero(t, c.MaxIncomingUniStreams)
}

func TestConfigChromeParrotOverrides(t *testing.T) {
	// ChromeParrot pins the values that show up in the transport parameters, so
	// whatever the caller asked for must be discarded.
	c := populateConfig(&Config{
		ChromeParrot:                   true,
		MaxIdleTimeout:                 time.Hour,
		InitialStreamReceiveWindow:     1234,
		InitialConnectionReceiveWindow: 4321,
		MaxIncomingStreams:             7,
		MaxIncomingUniStreams:          9,
		InitialPacketSize:              1350,
	})

	require.Equal(t, chromeMaxIdleTimeout, c.MaxIdleTimeout)
	require.EqualValues(t, chromeInitialMaxStreamData, c.InitialStreamReceiveWindow)
	require.EqualValues(t, chromeInitialMaxData, c.InitialConnectionReceiveWindow)
	require.EqualValues(t, chromeMaxIncomingStreams, c.MaxIncomingStreams)
	require.EqualValues(t, chromeMaxIncomingUniStreams, c.MaxIncomingUniStreams)
	require.EqualValues(t, chromeInitialPacketSize, c.InitialPacketSize)

	// The auto-tuning ceilings must never end up below the starting windows.
	require.GreaterOrEqual(t, c.MaxStreamReceiveWindow, c.InitialStreamReceiveWindow)
	require.GreaterOrEqual(t, c.MaxConnectionReceiveWindow, c.InitialConnectionReceiveWindow)
}

func TestConfigChromeParrotForcesDatagrams(t *testing.T) {
	// Chrome always advertises max_datagram_frame_size, so ChromeParrot must turn
	// datagrams on and clear Hysteria's OmitMaxDatagramFrameSize quirk; otherwise
	// the transport parameter set comes out one short of Chrome's.
	c := populateConfig(&Config{
		ChromeParrot:             true,
		EnableDatagrams:          false,
		OmitMaxDatagramFrameSize: true,
	})
	require.True(t, c.EnableDatagrams)
	require.False(t, c.OmitMaxDatagramFrameSize)
}
