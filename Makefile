GO ?= go
GOARCH ?= amd64
DIST := dist

.PHONY: build test vet release clean
build:
	mkdir -p $(DIST)
	CGO_ENABLED=0 GOOS=linux GOARCH=$(GOARCH) $(GO) build -trimpath -buildvcs=false -ldflags "-s -w" -o $(DIST)/osint-check-linux-$(GOARCH) .

test:
	$(GO) test -race ./...

vet:
	$(GO) vet -buildvcs=false ./...

release:
	$(MAKE) build GOARCH=amd64
	$(MAKE) build GOARCH=arm64

clean:
	rm -rf $(DIST)
