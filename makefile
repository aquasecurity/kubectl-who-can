SOURCES := $(shell find . -name '*.go')
BINARY := kubectl-who-can

build: kubectl-who-can

$(BINARY): $(SOURCES)
	GO111MODULE=on CGO_ENABLED=0 go build -o $(BINARY) ./cmd/kubectl-who-can.go

tests: $(SOURCES)
	GO111MODULE=on go test -v -short -race -timeout 30s -coverprofile=coverage.txt -covermode=atomic ./...

integration-tests: $(SOURCES)
	GO111MODULE=on GOOS=linux CGO_ENABLED=0 go test -v -c -o test/bin/integration_test test/integration_test.go
	@docker-compose -f test/docker-compose.yaml build --no-cache --force-rm
	@docker-compose -f test/docker-compose.yaml up --abort-on-container-exit --exit-code-from test
