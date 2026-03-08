VERSION ?= $(shell git describe --tags)

.PHONY: all clean test decipher .version

decipher: .version out/decipher

all: test .version out/decipher out/darwin-amd64/decipher out/darwin-arm64/decipher out/linux-amd64/decipher out/linux-arm64/decipher out/windows-amd64/decipher

clean:
	rm -rf out

test: internal/
	go test ./...

GO_INTERNAL_FILES=$(shell find internal -name '*.go')

out/decipher: out/.version cmd/decipher/main.go $(GO_INTERNAL_FILES)
	CGO_ENABLED=0 go build -ldflags "-X main.Version=$(VERSION)" -tags osusergo,netgo -o $@ ./cmd/decipher

out/darwin-amd64/decipher: out/.version cmd/decipher/main.go $(GO_INTERNAL_FILES)
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "-X main.Version=$(VERSION)" -tags osusergo,netgo -o $@ ./cmd/decipher

out/darwin-arm64/decipher: out/.version cmd/decipher/main.go $(GO_INTERNAL_FILES)
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -ldflags "-X main.Version=$(VERSION)" -tags osusergo,netgo -o $@ ./cmd/decipher

out/linux-amd64/decipher: out/.version cmd/decipher/main.go $(GO_INTERNAL_FILES)
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "-X main.Version=$(VERSION)" -tags osusergo,netgo -o $@ ./cmd/decipher

out/linux-arm64/decipher: out/.version cmd/decipher/main.go $(GO_INTERNAL_FILES)
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -ldflags "-X main.Version=$(VERSION)" -tags osusergo,netgo -o $@ ./cmd/decipher

out/windows-amd64/decipher: out/.version cmd/decipher/main.go $(GO_INTERNAL_FILES)
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "-X main.Version=$(VERSION)" -tags osusergo,netgo -o $@ ./cmd/decipher

.version:
ifneq ($(strip $(shell cat out/.version 2>/dev/null || true)),$(VERSION))
	[ -d out ] || mkdir out
	echo "$(VERSION)" > out/.version
endif
