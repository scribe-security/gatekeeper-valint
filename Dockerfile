# ARG BUILDPLATFORM="linux/amd64"
# ARG BUILDERIMAGE="golang:1.19-bullseye"
# ARG BASEIMAGE="gcr.io/distroless/static:nonroot"
# ARG BASEIMAGE="cgr.dev/chainguard/static:latest"
# ARG BASEIMAGE="alpine:latest"

ARG BASEIMAGE="scratch"

FROM alpine:latest AS base
RUN apk --no-cache add ca-certificates coreutils

FROM ${BASEIMAGE}

COPY ./gatekeeper-valint .

COPY --from=base /etc/ssl/certs /etc/ssl/certs

WORKDIR /

USER 65532:65532

ENTRYPOINT ["/gatekeeper-valint"]
