SOURCES := $(shell find . -name '*.go')
BINARY := kubectl-who-can
TARGET_OS := linux

build: kubectl-who-can

$(BINARY): $(SOURCES)
	GOOS=$(TARGET_OS) go build -o $(BINARY) .

tests:
	go test -race -timeout 30s -cover ./cmd ./check

