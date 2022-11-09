VERSION 0.6
ARG BASE_IMAGE=quay.io/kairos/core-opensuse:latest
ARG OSBUILDER_IMAGE=quay.io/kairos/osbuilder-tools
ARG GO_VERSION=1.18

build-challenger:
    FROM golang:alpine
    COPY . /work
    WORKDIR /work
    RUN CGO_ENABLED=0 go build -o kcrypt-discovery-challenger ./cmd/discovery
    SAVE ARTIFACT /work/kcrypt-discovery-challenger AS LOCAL kcrypt-discovery-challenger

image:
    FROM $BASE_IMAGE
    ARG IMAGE
    COPY +build-challenger/kcrypt-discovery-challenger /system/discovery/kcrypt-discovery-challenger
    SAVE IMAGE $IMAGE

iso:
    ARG OSBUILDER_IMAGE
    ARG ISO_NAME=challenger
    FROM $OSBUILDER_IMAGE
    RUN zypper in -y jq docker
    WORKDIR /build
    WITH DOCKER --allow-privileged --load $IMAGE=(+image --IMAGE=test)
        RUN /entrypoint.sh --name $ISO_NAME --debug build-iso --date=false --local test --output /build/
    END
    # See: https://github.com/rancher/elemental-cli/issues/228
    RUN sha256sum $ISO_NAME.iso > $ISO_NAME.iso.sha256
    SAVE ARTIFACT /build/$ISO_NAME.iso kairos.iso AS LOCAL build/$ISO_NAME.iso
    SAVE ARTIFACT /build/$ISO_NAME.iso.sha256 kairos.iso.sha256 AS LOCAL build/$ISO_NAME.iso.sha256

test:
    ARG GO_VERSION
    FROM golang:$GO_VERSION
    ENV CGO_ENABLED=0

    WORKDIR /work

    # Cache layer for modules
    COPY go.mod go.sum ./
    RUN go mod download && go mod verify

    RUN go install github.com/onsi/ginkgo/v2/ginkgo

    COPY . /work
    RUN PATH=$PATH:$GOPATH/bin ginkgo run --covermode=atomic --coverprofile=coverage.out -p -r pkg/challenger
    SAVE ARTIFACT coverage.out AS LOCAL coverage.out
