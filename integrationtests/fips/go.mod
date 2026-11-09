module github.com/apernet/quic-go/integrationtests/fips

go 1.26.0

// The version doesn't matter here, as we're replacing it with the currently checked out code anyway.
require github.com/apernet/quic-go v0.60.0

require github.com/stretchr/testify v1.12.1

require (
	github.com/andybalholm/brotli v1.0.6 // indirect
	github.com/klauspost/compress v1.17.4 // indirect
	github.com/refraction-networking/utls v1.8.2 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/crypto v0.54.0 // indirect
	golang.org/x/net v0.56.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
)

replace github.com/apernet/quic-go => ../../
