package handshake

import "golang.org/x/sys/unix"

func init() {
	// x/sys/cpu can recover features from registers even when the Go runtime
	// has no auxv and therefore cannot enable accelerated AES-GCM.
	if _, err := unix.Auxv(); err != nil {
		hasAESGCMHardwareSupport = false
	}
}
