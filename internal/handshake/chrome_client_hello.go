package handshake

import (
	"bytes"
	"slices"

	utls "github.com/refraction-networking/utls"
)

// chromeQUICClientHelloSpec returns the TLS ClientHello Chrome sends over QUIC.
//
// This is deliberately NOT one of uTLS's HelloChrome_* presets. Those are
// TLS-over-TCP (h2) fingerprints, and the QUIC ClientHello is a materially
// different message; using a TCP preset over QUIC produces a combination
// matching no real client, which is worse than not trying at all.
//
// The extension order is permuted per connection, hence the shuffle.
//
// alpn comes from the caller's tls.Config rather than being hardcoded:
// advertising a protocol the peer doesn't speak breaks the connection outright,
// which is worse than an imperfect fingerprint. The match is exact only for the
// protocol Chrome would negotiate.
func chromeQUICClientHelloSpec(alpn []string) *utls.ClientHelloSpec {
	if len(alpn) == 0 {
		alpn = []string{"h3"}
	}
	return &utls.ClientHelloSpec{
		// No GREASE suite here, unlike the TCP hello.
		CipherSuites: []uint16{
			utls.TLS_AES_128_GCM_SHA256,
			utls.TLS_AES_256_GCM_SHA384,
			utls.TLS_CHACHA20_POLY1305_SHA256,
		},
		CompressionMethods: []byte{0x00},
		Extensions: utls.ShuffleChromeTLSExtensions([]utls.TLSExtension{
			&utls.SNIExtension{},
			// No GREASE curve, unlike the TCP hello.
			&utls.SupportedCurvesExtension{Curves: []utls.CurveID{
				utls.X25519MLKEM768,
				utls.X25519,
				utls.CurveP256,
				utls.CurveP384,
			}},
			&utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{
				utls.ECDSAWithP256AndSHA256,
				utls.PSSWithSHA256,
				utls.PKCS1WithSHA256,
				utls.ECDSAWithP384AndSHA384,
				utls.PSSWithSHA384,
				utls.PKCS1WithSHA384,
				utls.PSSWithSHA512,
				utls.PKCS1WithSHA512,
				utls.PKCS1WithSHA1,
			}},
			&utls.ALPNExtension{AlpnProtocols: alpn},
			&utls.UtlsCompressCertExtension{Algorithms: []utls.CertCompressionAlgo{
				utls.CertCompressionBrotli,
			}},
			// TLS 1.3 only, again with no GREASE version.
			&utls.SupportedVersionsExtension{Versions: []uint16{utls.VersionTLS13}},
			&utls.PSKKeyExchangeModesExtension{Modes: []uint8{utls.PskModeDHE}},
			// The ML-KEM share is what pushes the ClientHello past a single packet,
			// giving the characteristic two Initial datagrams.
			&utls.KeyShareExtension{KeyShares: []utls.KeyShare{
				{Group: utls.X25519MLKEM768},
				{Group: utls.X25519},
			}},
			// Populated from quic-go's own marshalled parameters; see
			// utlsQUICConn.SetTransportParameters.
			&utls.QUICTransportParametersExtension{},
			// ALPS at the newer codepoint; uTLS's presets use the older one.
			&utls.ApplicationSettingsExtensionNew{SupportedProtocols: alpn},
			// An ECH extension is always present: real when a config is available
			// from DNS, GREASE otherwise. GREASE is right here, and is structurally
			// indistinguishable from the real thing without decrypting it.
			utls.BoringGREASEECH(),
			// uTLS has no native support for trust_anchors, so it goes out raw.
			&utls.GenericExtension{Id: extensionTrustAnchors, Data: chromeTrustAnchorsData},
		}),
	}
}

// extensionTrustAnchors is the TLS trust_anchors extension
// (draft-ietf-tls-trust-anchor-ids).
const extensionTrustAnchors uint16 = 0xca34

// chromeTrustAnchorIDs are the trust anchor IDs Chrome requests, in binary
// relative OID form. The set follows Chrome's root store and changes across
// releases, so it is pinned like the transport parameter values.
var chromeTrustAnchorIDs = [][]byte{
	{0x82, 0xdf, 0x13, 0x02, 0x01},
	{0x82, 0xdf, 0x13, 0x02, 0x06},
	{0x82, 0xdf, 0x13, 0x02, 0x0d},
	{0x82, 0xdf, 0x13, 0x02, 0x0e},
	{0x82, 0xdf, 0x13, 0x02, 0x0f},
	{0x82, 0xdf, 0x13, 0x02, 0x12},
	{0x82, 0xdf, 0x13, 0x02, 0x13},
	{0x82, 0xdf, 0x13, 0x02, 0x14},
	{0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x07},
	{0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x08},
	{0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x09},
	{0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x0a},
	{0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x0b},
	{0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x0c},
	{0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x0d},
	{0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x12},
	{0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x13},
	{0xd6, 0x79, 0x09, 0x01},
	{0xd6, 0x79, 0x09, 0x04},
	{0xd6, 0x79, 0x09, 0x05},
	{0xd6, 0x79, 0x09, 0x06},
	{0xd6, 0x79, 0x09, 0x07},
	{0xd6, 0x79, 0x09, 0x08},
	{0xd6, 0x79, 0x09, 0x0a},
	{0xd6, 0x79, 0x09, 0x0b},
	{0xd6, 0x79, 0x09, 0x0c},
	{0xd6, 0x79, 0x09, 0x0d},
	{0xd6, 0x79, 0x09, 0x0f},
}

var chromeTrustAnchorsData = encodeTrustAnchorIDs(chromeTrustAnchorIDs)

// encodeTrustAnchorIDs encodes the extension body: a 16-bit length, then each ID
// 8-bit length-prefixed. The IDs are sorted first, as Chrome encodes them, so the
// order is the same on every connection.
func encodeTrustAnchorIDs(ids [][]byte) []byte {
	sorted := slices.Clone(ids)
	slices.SortFunc(sorted, bytes.Compare)

	var list []byte
	for _, id := range sorted {
		list = append(list, byte(len(id)))
		list = append(list, id...)
	}
	return append([]byte{byte(len(list) >> 8), byte(len(list))}, list...)
}
