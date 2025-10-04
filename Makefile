build:
	GOOS=darwin GOARCH=amd64 go build -o dist/vne-darwin-amd64 ./cmd/vne-agent
	GOOS=linux  GOARCH=amd64 go build -o dist/vne-linux-amd64  ./cmd/vne-agent
	GOOS=windows GOARCH=amd64 go build -o dist/vne-win-amd64.exe ./cmd/vne-agent

run:
	go run ./cmd/vne-agent
