module github.com/quic-go/quic-go

go 1.26.0

require (
	github.com/quic-go/go-ossfuzz-seeds v0.1.0
	github.com/quic-go/qpack v0.6.0
	github.com/refraction-networking/utls v1.8.2
	github.com/stretchr/testify v1.12.1
	go.uber.org/mock v0.5.2
	golang.org/x/crypto v0.54.0
	golang.org/x/net v0.56.0
	golang.org/x/sync v0.22.0
	golang.org/x/sys v0.47.0
)

require (
	github.com/andybalholm/brotli v1.0.6 // indirect
	github.com/jordanlewis/gcassert v0.0.0-20250430164644-389ef753e22e // indirect
	github.com/klauspost/compress v1.17.4 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/mod v0.37.0 // indirect
	golang.org/x/text v0.40.0 // indirect
	golang.org/x/tools v0.47.0 // indirect
)

tool (
	github.com/jordanlewis/gcassert/cmd/gcassert
	go.uber.org/mock/mockgen
)
