ifeq ($(DEFAULT_BASE_URL),)
DEFAULT_BASE_URL:="https://cloudgate.example.com"
endif

GIT_COMMIT ?= $(shell git log -1 --pretty=format:"%H")


default:
	go build -ldflags "-X main.Version=git:${GIT_COMMIT}"

clean:
	rm -f cg-systray-client
	rm -f cg-systray-client.Darwin
	rm -f cg-systray-client.Linux

all: darwin
# -X main.DefaultBaseURL=${DEFAULT_BASE_URL}"

darwin:
	env GOOS=darwin GOARCH=amd64 go build -ldflags "-X main.Version=git:${GIT_COMMIT}  -X main.DefaultBaseURL=${DEFAULT_BASE_URL}"  -o cg-systray-client.Darwin

signdarwin: cg-systray-client.Darwin
	codesign -s 69MB9635QH cg-systray-client.Darwin

windows: 
	env GOOS=windows  GOARCH=amd64 go build  -ldflags "-X main.Version=git:${GIT_COMMIT}  -X main.DefaultBaseURL=${DEFAULT_BASE_URL}" -ldflags -H=windowsgui -o cg-systray-client.exe

linux:
	env GOOS=linux GOARCH=amd64 go build -ldflags "-X main.Version=git:${GIT_COMMIT} -X main.DefaultBaseURL=${DEFAULT_BASE_URL}"  -o cg-systray-client.Linux
