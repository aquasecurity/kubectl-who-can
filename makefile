SOURCES := $(shell find . -name '*.go')
BINARY := kubectl-who-can

build: kubectl-who-can

$(BINARY): $(SOURCES)
	GO111MODULE=on go build -o $(BINARY) ./cmd/kubectl-who-can.go

tests: $(SOURCES)
	GO111MODULE=on go test -v -short -race  -timeout 30s -coverprofile=coverage.txt -covermode=atomic ./...
