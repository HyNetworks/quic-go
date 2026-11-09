//go:build !openbsd

package quic

const desiredBufferSize = 8 << 20 // 8 MiB
