FROM alpine:latest AS build
RUN apk --no-cache add ca-certificates coreutils

FROM scratch

ARG DESCRIPTION
ARG BUILD_DATE
ARG BUILD_VERSION
ARG VCS_REF
ARG VCS_URL
ARG PROJECT_NAME
ENV PROJECT_NAME=$PROJECT_NAME

LABEL org.opencontainers.image.created=$BUILD_DATE
LABEL org.opencontainers.image.title=$PROJECT_NAME
LABEL org.opencontainers.image.description=$DESCRIPTION
LABEL org.opencontainers.image.source=$VCS_URL
LABEL org.opencontainers.image.revision=$VCS_REF
LABEL org.opencontainers.image.vendor="Scribe security, Inc."
LABEL org.opencontainers.image.version=$BUILD_VERSION

LABEL io.artifacthub.package.readme-url="https://raw.githubusercontent.com/scribe-security/$PROJECT_NAME/README.md"
LABEL io.artifacthub.package.name=$PROJECT_NAME
LABEL io.artifacthub.package.license=Apache-2.0 
LABEL io.artifacthub.package.vendor="Scribe security, Inc."


COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build / /
RUN /bin/mkdir -p /etc/scribe/keys /home/scribe/
COPY . /home/scribe/
WORKDIR /home/scribe/

USER 65532:65532


ENV PATH="/home/scribe/:${PATH}"
ENTRYPOINT [ "/home/scribe/docker/entrypoint.sh", "/home/scribe/${PROJECT_NAME}" ]