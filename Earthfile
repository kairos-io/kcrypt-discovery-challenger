VERSION 0.6
ARG BASE_IMAGE=quay.io/kairos/core-ubuntu:latest
ARG OSBUILDER_IMAGE=quay.io/kairos/osbuilder-tools
ARG GO_VERSION=1.18
ARG LUET_VERSION=0.33.0

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

image-rootfs:
  FROM +image
  SAVE ARTIFACT --keep-own /. rootfs

grub-files:
    FROM alpine
    RUN apk add wget
    # Hack to see if this gets fixed:
    # https://github.com/earthly/earthly/issues/847
    RUN ifconfig eth0 mtu 1200
    RUN ifconfig cni0 mtu 1200
    RUN wget https://raw.githubusercontent.com/c3os-io/c3os/master/overlay/files-iso/boot/grub2/grub.cfg -O grub.cfg
    SAVE ARTIFACT --keep-own grub.cfg grub.cfg

iso:
    ARG OSBUILDER_IMAGE
    ARG ISO_NAME=challenger
    FROM $OSBUILDER_IMAGE
    WORKDIR /build
    COPY --keep-own +grub-files/grub.cfg /build/files-iso/boot/grub2/grub.cfg
    COPY --keep-own +image-rootfs/rootfs /build/rootfs
    RUN /entrypoint.sh --name $ISO_NAME --debug build-iso --squash-no-compression --date=false --local --overlay-iso /build/files-iso --output /build/ dir:/build/rootfs
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

    RUN go get github.com/onsi/gomega/...
    RUN go get github.com/onsi/ginkgo/v2/ginkgo/internal@v2.1.4
    RUN go get github.com/onsi/ginkgo/v2/ginkgo/generators@v2.1.4
    RUN go get github.com/onsi/ginkgo/v2/ginkgo/labels@v2.1.4
    RUN go install -mod=mod github.com/onsi/ginkgo/v2/ginkgo

    COPY . /work
    RUN PATH=$PATH:$GOPATH/bin ginkgo run --covermode=atomic --coverprofile=coverage.out -p -r pkg/challenger cmd/discovery/client
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
    RUN zypper in -y go git qemu-x86 qemu-arm qemu-tools swtpm docker jq docker-compose make glibc libopenssl-devel curl gettext-runtime
    ENV GOPATH="/go"

    COPY . /test
    WORKDIR /test

    RUN go install -mod=mod github.com/onsi/ginkgo/v2/ginkgo
    RUN go get github.com/onsi/gomega/...
    RUN go get github.com/onsi/ginkgo/v2/ginkgo/internal@v2.7.1
    RUN go get github.com/onsi/ginkgo/v2/ginkgo/generators@v2.7.1
    RUN go get github.com/onsi/ginkgo/v2/ginkgo/labels@v2.7.1

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

e2e-tests:
    FROM +e2e-tests-image
    ARG LABEL

    WITH DOCKER --allow-privileged
        RUN ./scripts/e2e-tests.sh
    END
