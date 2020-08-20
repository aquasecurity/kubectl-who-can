SOURCES := $(shell find . -name '*.go')
BINARY := kubectl-who-can

build: kubectl-who-can

$(BINARY): $(SOURCES)
	GO111MODULE=on CGO_ENABLED=0 go build -o $(BINARY) ./cmd/kubectl-who-can/main.go

unit-tests: $(SOURCES)
	GO111MODULE=on go test -v -short -race -timeout 30s -coverprofile=coverage.txt -covermode=atomic ./...

integration-tests: $(SOURCES)
	GO111MODULE=on go test -v test/integration_test.go

.PHONY: clean
clean:
	rm $(BINARY)
	rm coverage.txt
