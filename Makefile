GOPATH ?= ${shell go env GOPATH}

GIT_COMMIT ?= $(shell git log -1 --pretty=format:"%H")

# jenkins/github integration sets the GIT_BRANCH for you including the remote
# so we first create the variable if not exists and then take the
# last element
GIT_BRANCH ?= $(shell git rev-parse --abbrev-ref HEAD)
GIT_BRANCH2 = $(shell echo ${GIT_BRANCH} | rev | cut -d/ -f1 | rev)

# This is how we want to name the binary output
BINARY=cloud-gate
#
# # These are the values we want to pass for Version and BuildTime
VERSION=1.3.1

all:
	cd cmd/cloud-gate; go install -ldflags "-X main.Version=${VERSION}"
	cd cmd/cg-client; go install -ldflags "-X main.Version=${VERSION}"
	cd cmd/cg-systray-client; go install -ldflags "-X main.Version=${VERSION}"

build:
	go build -ldflags "-X main.Version=${VERSION}" -o bin/   ./...

get-deps:
	go get -t ./...

update-deps:
	go get -u ./...
	go mod tidy

clean:
	rm -f bin/*
	rm -f cloud-gate-*.tar.gz
	rm -f cloud-gate-*.rpm
	rm -f cloud-gate_*.deb

${BINARY}-${VERSION}.tar.gz:
	mkdir ${BINARY}-${VERSION}
	rsync -av --exclude="config.yml" --exclude="*.pem" --exclude="*.out" lib/ ${BINARY}-${VERSION}/lib/
	rsync -av --exclude="config.yml" --exclude="*.pem" --exclude="*.out" --exclude="*.key" cmd/ ${BINARY}-${VERSION}/cmd/
	rsync -av --exclude="config.yml" --exclude="*.pem" --exclude="*.out" --exclude="*.key" broker/ ${BINARY}-${VERSION}/broker/
	rsync -av --exclude="config.yml" --exclude="*.pem" --exclude="*.out" --exclude="*.key" docs/ ${BINARY}-${VERSION}/docs/
	rsync -av  misc/ ${BINARY}-${VERSION}/misc/
	cp LICENSE Makefile cloud-gate.spec README.md go.mod go.sum ${BINARY}-${VERSION}/
	tar -cvzf ${BINARY}-${VERSION}.tar.gz ${BINARY}-${VERSION}/
	rm -rf ${BINARY}-${VERSION}/

rpm:    ${BINARY}-${VERSION}.tar.gz
	rpmbuild -ta ${BINARY}-${VERSION}.tar.gz

tar:    ${BINARY}-${VERSION}.tar.gz


format:
	gofmt -s -w .

format-imports:
	goimports -w .


test:
	@find * -name '*_test.go' |\
	sed -e 's@^@github.com/Cloud-Foundations/cloud-gate/@' -e 's@/[^/]*$$@@' |\
	sort -u | xargs go test


dockerpackagebuild:
	@echo GIT_COMMIT=$(GIT_COMMIT)
	@echo GIT_BRANCH2=$(GIT_BRANCH2)
	docker build -f Dockerfile.packagebuilder --build-arg GIT_COMMIT=$(GIT_COMMIT) -t cloud-gate-packagebuilder --no-cache .
	docker run cloud-gate-packagebuilder cat /root/rpmbuild/RPMS/x86_64/cloud-gate-${VERSION}-1.x86_64.rpm > cloud-gate-${VERSION}-1.x86_64.rpm
	docker run cloud-gate-packagebuilder cat cloud-gate_${VERSION}-2_amd64.deb > cloud-gate_${VERSION}-2_amd64.deb
	#docker run cloud-gate-packagebuilder cat /go/bin/cloud-gate > cloud-gate.linux
