GIT_COMMIT ?= $(shell git log -1 --pretty=format:"%H")


default:
	go build -ldflags "-X main.Version=git:${GIT_COMMIT}"

clean:
	rm -f cg-systray-client
	rm -f cg-systray-client.Darwin

all: darwin

darwin:
	env GOOS=darwin GOARCH=amd64 go build -ldflags "-X main.Version=git:${GIT_COMMIT}"  -o cg-systray-client.Darwin
