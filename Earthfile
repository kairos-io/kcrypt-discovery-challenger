VERSION 0.6
ARG BASE_IMAGE=quay.io/kairos/core-opensuse:latest
ARG OSBUILDER_IMAGE=quay.io/kairos/osbuilder-tools


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
