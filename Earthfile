VERSION 0.6

# renovate: datasource=github-releases depName=kairos-io/kairos
ARG KAIROS_VERSION="v3.5.3"
ARG KAIROS_INIT_VERSION="v0.5.20"
ARG UBUNTU_VERSION="24.04"
# Use our custom base image instead of the upstream one
ARG BASE_IMAGE=+custom-kairos-base

ARG OSBUILDER_IMAGE=quay.io/kairos/osbuilder-tools
# renovate: datasource=docker depName=golang
ARG GO_VERSION=1.25-bookworm
ARG LUET_VERSION=0.33.0

build-challenger:
    FROM +go-deps
    COPY . /work
    WORKDIR /work
    RUN CGO_ENABLED=1 go build -o kcrypt-discovery-challenger ./cmd/discovery
    SAVE ARTIFACT /work/kcrypt-discovery-challenger kcrypt-discovery-challenger AS LOCAL kcrypt-discovery-challenger

kairos-init-binary:
    ARG KAIROS_INIT_VERSION
    FROM quay.io/kairos/kairos-init:${KAIROS_INIT_VERSION}
    SAVE ARTIFACT /kairos-init kairos-init

custom-kairos-base:
    ARG UBUNTU_VERSION
    ARG KAIROS_INIT_VERSION
    FROM ubuntu:${UBUNTU_VERSION}

    # Copy kairos-init from the kairos-init target
    COPY +kairos-init-binary/kairos-init /kairos-init

    # STAGE 1: Run kairos-init INSTALL stage only (installs packages, kernel, etc.)
    # This will install the default immucore and kairos-agent from packages
    RUN /kairos-init -l debug -m "generic" -t "false" -s "install" --version "${KAIROS_INIT_VERSION}"

    # STAGE 1.5: Replace the installed binaries with our custom versions
    # This happens AFTER package installation but BEFORE initramfs generation
    COPY immucore /usr/bin/immucore
    COPY kairos-agent /usr/bin/kairos-agent

    # Verify our custom binaries are in place
    RUN echo "Custom immucore version:" && /usr/bin/immucore --version && \
        echo "Custom kairos-agent in place"

    # STAGE 2: Run kairos-init INIT stage (generates initramfs with our custom binaries)
    RUN /kairos-init -l debug -m "generic" -t "false" -s "init" --version "${KAIROS_INIT_VERSION}" && \
        /kairos-init validate -t "false"

    # Verify the initramfs was created
    RUN ls -lh /boot/initrd && echo "Custom Kairos base image built successfully with custom binaries"

    SAVE IMAGE custom-kairos-base:latest

image:
    FROM +custom-kairos-base
    ARG IMAGE
    COPY +build-challenger/kcrypt-discovery-challenger /system/discovery/kcrypt-discovery-challenger

    # No need to copy binaries or regenerate initramfs - already done in custom-kairos-base!

    # Verify our custom immucore is in place
    RUN echo "Final immucore version in image:" && /usr/bin/immucore --version

    # Add hardcoded root password for debugging
    RUN echo 'root:root' | chpasswd

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
    # Install OpenSSL development libraries needed for TPM simulator
    RUN apt-get update && apt-get install -y libssl-dev && rm -rf /var/lib/apt/lists/*
    COPY go.mod go.sum ./
    RUN go mod download
    RUN go mod verify
    SAVE ARTIFACT go.mod AS LOCAL go.mod
    SAVE ARTIFACT go.sum AS LOCAL go.sum

test:
    FROM +go-deps
    ENV CGO_ENABLED=1
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
    RUN zypper in -y go1.23 git qemu-x86 qemu-arm qemu-tools swtpm docker jq docker-compose make glibc libopenssl-devel curl gettext-runtime awk envsubst
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
