package self_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/apernet/quic-go"
	"github.com/stretchr/testify/require"
)

// chromeCompatibleTLSConfigs returns a server/client config pair using an ECDSA
// P-256 certificate.
//
// The shared test helpers use Ed25519, which a Chrome-parroting client cannot
// verify: its signature_algorithms extension advertises no Ed25519 scheme, so
// such a server has nothing to sign with and aborts. That is faithful behavior
// rather than a defect, but it is a deployment constraint;
// TestChromeParrotRejectsEd25519Server pins it down.
func chromeCompatibleTLSConfigs(t *testing.T) (server, client *tls.Config) {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "chrome-parrot test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	ca, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, ca, &leafKey.PublicKey, caKey)
	require.NoError(t, err)

	pool := x509.NewCertPool()
	pool.AddCert(ca)

	const alpn = "h3" // required for an exact match
	return &tls.Config{
			Certificates: []tls.Certificate{{
				Certificate: [][]byte{leafDER},
				PrivateKey:  leafKey,
			}},
			NextProtos: []string{alpn},
		}, &tls.Config{
			RootCAs:    pool,
			ServerName: "localhost",
			NextProtos: []string{alpn},
		}
}

// TestChromeParrotHandshake is the load-bearing check on Config.ChromeParrot: the
// uTLS ClientHello, the chaos-protected Initial packets and the reshaped
// transport parameters must still produce a working connection. Cosmetics that
// break interop are worse than no cosmetics.
func TestChromeParrotHandshake(t *testing.T) {
	serverConf, clientConf := chromeCompatibleTLSConfigs(t)

	server, err := quic.Listen(newUDPConnLocalhost(t), serverConf, getQuicConfig(nil))
	require.NoError(t, err)
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	clientConn, err := quic.Dial(ctx, newUDPConnLocalhost(t), server.Addr(),
		clientConf, getQuicConfig(&quic.Config{ChromeParrot: true}))
	require.NoError(t, err)
	defer clientConn.CloseWithError(0, "")

	serverConn, err := server.Accept(ctx)
	require.NoError(t, err)
	defer serverConn.CloseWithError(0, "")

	// Only TLS 1.3 suites and an ML-KEM key share are offered, so confirm we
	// actually negotiated TLS 1.3 over that.
	state := clientConn.ConnectionState().TLS
	require.Equal(t, uint16(tls.VersionTLS13), state.Version)
	require.True(t, state.HandshakeComplete)

	// Push enough data to cross the shredded-CRYPTO reassembly path and exercise
	// the pinned flow control windows.
	const payloadLen = 256 << 10
	go func() {
		str, err := serverConn.OpenUniStreamSync(ctx)
		if err != nil {
			return
		}
		defer str.Close()
		str.Write(PRDataLong[:payloadLen])
	}()

	str, err := clientConn.AcceptUniStream(ctx)
	require.NoError(t, err)
	data, err := io.ReadAll(str)
	require.NoError(t, err)
	require.Equal(t, PRDataLong[:payloadLen], data)
}

// TestChromeParrotRejectsEd25519Server documents a deployment constraint: with no
// Ed25519 signature scheme advertised, a ChromeParrot client cannot handshake
// against a server presenting an Ed25519 certificate. If this test starts
// passing, the ClientHello has drifted.
func TestChromeParrotRejectsEd25519Server(t *testing.T) {
	// The shared helpers issue Ed25519 certificates.
	server, err := quic.Listen(newUDPConnLocalhost(t), getTLSConfig(), getQuicConfig(nil))
	require.NoError(t, err)
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err = quic.Dial(ctx, newUDPConnLocalhost(t), server.Addr(),
		getTLSClientConfig(), getQuicConfig(&quic.Config{ChromeParrot: true}))
	require.Error(t, err)
	require.Contains(t, err.Error(), "handshake failure")
}

// TestChromeParrotAppliesChromeTransportParameters checks that the peer receives
// the pinned values rather than quic-go's, since what goes on the wire is the
// whole point.
func TestChromeParrotAppliesChromeTransportParameters(t *testing.T) {
	serverConf, clientConf := chromeCompatibleTLSConfigs(t)

	server, err := quic.Listen(newUDPConnLocalhost(t), serverConf, getQuicConfig(nil))
	require.NoError(t, err)
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	clientConn, err := quic.Dial(ctx, newUDPConnLocalhost(t), server.Addr(),
		clientConf, getQuicConfig(&quic.Config{ChromeParrot: true}))
	require.NoError(t, err)
	defer clientConn.CloseWithError(0, "")

	serverConn, err := server.Accept(ctx)
	require.NoError(t, err)
	defer serverConn.CloseWithError(0, "")

	// The server may open up to the advertised initial_max_streams_bidi. quic-go's
	// own default differs, so this passes only if the pinned values reached the
	// wire and were honored.
	for i := range chromeParrotBidiStreamLimit {
		str, err := serverConn.OpenStream()
		require.NoError(t, err, "opening stream %d within the advertised limit", i)
		require.NotNil(t, str)
	}
}

// The advertised initial_max_streams_bidi.
const chromeParrotBidiStreamLimit = 100

// TestChromeParrotRejectsUnsupportedTLSConfig checks that config fields which
// cannot be carried across to uTLS fail loudly instead of being silently dropped.
// For a verification callback, silently dropping it would be a security bug.
func TestChromeParrotRejectsUnsupportedTLSConfig(t *testing.T) {
	_, clientConf := chromeCompatibleTLSConfigs(t)
	clientConf.VerifyConnection = func(tls.ConnectionState) error { return nil }

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := quic.Dial(ctx, newUDPConnLocalhost(t), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234},
		clientConf, getQuicConfig(&quic.Config{ChromeParrot: true}))
	require.Error(t, err)
	require.Contains(t, err.Error(), "VerifyConnection is not supported")
}
