VERSION 0.6

# renovate: datasource=github-releases depName=kairos-io/kairos
ARG KAIROS_VERSION="v2.5.0"
ARG BASE_IMAGE=quay.io/kairos/ubuntu:23.10-core-amd64-generic-$KAIROS_VERSION

ARG OSBUILDER_IMAGE=quay.io/kairos/osbuilder-tools
# renovate: datasource=docker depName=golang
ARG GO_VERSION=1.23-bookworm
ARG LUET_VERSION=0.33.0

build-challenger:
    FROM +go-deps
    COPY . /work
    WORKDIR /work
    RUN CGO_ENABLED=0 go build -o kcrypt-discovery-challenger ./cmd/discovery
    SAVE ARTIFACT /work/kcrypt-discovery-challenger kcrypt-discovery-challenger AS LOCAL kcrypt-discovery-challenger

image:
    FROM $BASE_IMAGE
    ARG IMAGE
    COPY +build-challenger/kcrypt-discovery-challenger /system/discovery/kcrypt-discovery-challenger
    SAVE IMAGE $IMAGE

image-rootfs:
    FROM +image
    SAVE ARTIFACT --keep-own /. rootfs

iso:
    ARG OSBUILDER_IMAGE
    ARG ISO_NAME=challenger
    FROM $OSBUILDER_IMAGE
    WORKDIR /build
    COPY --keep-own +image-rootfs/rootfs /build/rootfs
    RUN /entrypoint.sh --name $ISO_NAME --debug build-iso --squash-no-compression --date=false --output /build/ dir:/build/rootfs
    SAVE ARTIFACT /build/$ISO_NAME.iso kairos.iso AS LOCAL build/$ISO_NAME.iso
    SAVE ARTIFACT /build/$ISO_NAME.iso.sha256 kairos.iso.sha256 AS LOCAL build/$ISO_NAME.iso.sha256

go-deps:
    ARG GO_VERSION
    FROM golang:$GO_VERSION
    WORKDIR /build
    COPY go.mod go.sum ./
    RUN go mod download
    RUN go mod verify
    SAVE ARTIFACT go.mod AS LOCAL go.mod
    SAVE ARTIFACT go.sum AS LOCAL go.sum

test:
    FROM +go-deps
    ENV CGO_ENABLED=0
    WORKDIR /work

    COPY . .
    RUN go run github.com/onsi/ginkgo/v2/ginkgo run --covermode=atomic --coverprofile=coverage.out -p -r pkg/challenger cmd/discovery/client
    SAVE ARTIFACT coverage.out AS LOCAL coverage.out

# Generic targets
# usage e.g. ./earthly.sh +datasource-iso --CLOUD_CONFIG=tests/assets/qrcode.yaml
datasource-iso:
    ARG OSBUILDER_IMAGE
    ARG CLOUD_CONFIG
    FROM $OSBUILDER_IMAGE
    RUN zypper in -y mkisofs
    WORKDIR /build
    RUN touch meta-data

    COPY ${CLOUD_CONFIG} user-data
    RUN cat user-data
    RUN mkisofs -output ci.iso -volid cidata -joliet -rock user-data meta-data
    SAVE ARTIFACT /build/ci.iso iso.iso AS LOCAL build/datasource.iso

luet:
    FROM quay.io/luet/base:$LUET_VERSION
    SAVE ARTIFACT /usr/bin/luet /luet

e2e-tests-image:
    FROM opensuse/tumbleweed
    RUN zypper in -y go1.22 git qemu-x86 qemu-arm qemu-tools swtpm docker jq docker-compose make glibc libopenssl-devel curl gettext-runtime awk envsubst
    ENV GOPATH="/go"

    COPY . /test
    WORKDIR /test

    IF [ -e /test/build/kairos.iso ]
        ENV ISO=/test/build/kairos.iso
    ELSE
        COPY +iso/kairos.iso kairos.iso
        ENV ISO=/test/kairos.iso
    END

    COPY +luet/luet /usr/bin/luet
    RUN mkdir -p /etc/luet/repos.conf.d/
    RUN luet repo add -y kairos --url quay.io/kairos/packages --type docker
    RUN LUET_NOLOCK=true luet install -y container/kubectl utils/k3d

controller-latest:
    FROM DOCKERFILE .
    SAVE IMAGE controller:latest

e2e-tests:
    FROM +e2e-tests-image
    ARG LABEL
    RUN make test # This also generates the latest controllers automatically, we do that before building the docker image with them
    WITH DOCKER --allow-privileged --load controller:latest=+controller-latest
        RUN ./scripts/e2e-tests.sh
    END

lint:
    BUILD +yamllint

yamllint:
    FROM cytopia/yamllint
    COPY . .
    RUN yamllint .github/workflows/
