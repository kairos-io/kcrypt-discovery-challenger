VERSION 0.6
ARG BASE_IMAGE=quay.io/kairos/core-ubuntu:latest
ARG OSBUILDER_IMAGE=quay.io/kairos/osbuilder-tools
# renovate: datasource=docker depName=golang
ARG GO_VERSION=1.20
ARG LUET_VERSION=0.33.0

build-challenger:
    FROM golang:alpine
    COPY . /work
    WORKDIR /work
    RUN CGO_ENABLED=0 go build -o kcrypt-discovery-challenger ./cmd/discovery
    SAVE ARTIFACT /work/kcrypt-discovery-challenger kcrypt-discovery-challenger AS LOCAL kcrypt-discovery-challenger

image:
    FROM $BASE_IMAGE
    ARG IMAGE
    # TEST KCRYPT FROM BRANCH
    ARG KCRYPT_DEV
    ARG KCRYPT_DEV_BRANCH=main
    IF [ "$KCRYPT_DEV" = "true" ]
        RUN rm /usr/bin/kcrypt
        COPY github.com/kairos-io/kcrypt:$KCRYPT_DEV_BRANCH+build-kcrypt/kcrypt /usr/bin/kcrypt
    END
    ARG IMMUCORE_DEV
    ARG IMMUCORE_DEV_BRANCH=master
    IF [ "$IMMUCORE_DEV" = "true" ]
        RUN rm -Rf /usr/lib/dracut/modules.d/28immucore
        RUN rm /etc/dracut.conf.d/10-immucore.conf
        RUN rm /etc/dracut.conf.d/02-kairos-setup-initramfs.conf || exit 0
        RUN rm /etc/dracut.conf.d/50-kairos-initrd.conf || exit 0
        COPY github.com/kairos-io/immucore:$IMMUCORE_DEV_BRANCH+build-immucore/immucore /usr/bin/immucore
        COPY github.com/kairos-io/immucore:$IMMUCORE_DEV_BRANCH+dracut-artifacts/28immucore /usr/lib/dracut/modules.d/28immucore
        COPY github.com/kairos-io/immucore:$IMMUCORE_DEV_BRANCH+dracut-artifacts/10-immucore.conf /etc/dracut.conf.d/10-immucore.conf
        # Need to rerun dracut so the updated binaries get in the initramfs
        RUN --no-cache kernel=$(ls /lib/modules | head -n1) && depmod -a "${kernel}"
        RUN --no-cache kernel=$(ls /lib/modules | head -n1) && dracut -f "/boot/initrd-${kernel}" "${kernel}" && ln -sf "initrd-${kernel}" /boot/initrd
    END

   # END
    COPY +build-challenger/kcrypt-discovery-challenger /system/discovery/kcrypt-discovery-challenger
    SAVE IMAGE $IMAGE

image-rootfs:
  FROM +image
  SAVE ARTIFACT --keep-own /. rootfs

grub-files:
    FROM alpine
    RUN apk add wget
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

    COPY . /work
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
    RUN zypper in -y go git qemu-x86 qemu-arm qemu-tools swtpm docker jq docker-compose make glibc libopenssl-devel curl gettext-runtime
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

e2e-tests:
    FROM +e2e-tests-image
    ARG LABEL

    WITH DOCKER --allow-privileged
        RUN ./scripts/e2e-tests.sh
    END

lint:
    BUILD +yamllint

yamllint:
    FROM cytopia/yamllint
    COPY . .
    RUN yamllint .github/workflows/
