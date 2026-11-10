test-coverage:
	mkdir -p coverage
	go test -v -race \
		-coverpkg=./portscan,./internal/... \
		-coverprofile=./coverage/cover.out \
		./tests && \
	go tool cover -html=./coverage/cover.out -o ./coverage/cover.html

full-verification:
	go version
	go fmt ./...
	go vet ./...
	go test ./...
	go test -race ./...

#go run . -hosts 127.0.0.1 -ports 80,443,40000 -concurrency 1 -timeout 5s