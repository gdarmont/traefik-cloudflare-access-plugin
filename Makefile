.PHONY: lint test vendor clean build

export GO111MODULE=on

default: lint test build

lint:
	golangci-lint run

test:
	go test -v -cover ./...

build:
	@go build -o plugin.wasm ./cloudflare-auth-verifier.go

vendor:
	go mod vendor

clean:
	rm -rf ./vendor