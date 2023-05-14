ARG BASE_IMAGE=docker.io/library/ubuntu:22.04@sha256:9a0bdde4188b896a372804be2384015e90e3f84906b750c1a53539b585fbbe7f
####################################################################################################
# Builder image
# Initial stage which pulls prepares build dependencies and CLI tooling we need for our final image
# Also used as the image in CI jobs so needs all dependencies
####################################################################################################
FROM docker.io/library/golang:1.19.9@sha256:9613596d7405705447f36440a59a3a2a1d22384c7568ae1838d0129964c5ba13 AS builder

RUN echo 'deb http://deb.debian.org/debian buster-backports main' >> /etc/apt/sources.list

RUN apt-get update && apt-get install --no-install-recommends -y \
    openssh-server \
    nginx \
    unzip \
    fcgiwrap \
    git \
    #git-lfs \
    make \
    wget \
    gcc \
    sudo \
    zip && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

WORKDIR /tmp

COPY hack/install.sh hack/tool-versions.sh ./
COPY hack/installers installers

RUN ./install.sh helm-linux && \
    INSTALL_PATH=/usr/local/bin ./install.sh kustomize

####################################################################################################
# Argo CD Base - used as the base for both the release and dev argocd images
####################################################################################################
FROM $BASE_IMAGE AS argocd-base

LABEL org.opencontainers.image.source="https://github.com/argoproj/argo-cd"

USER root

ENV ARGOCD_USER_ID=999
ENV DEBIAN_FRONTEND=noninteractive

RUN groupadd -g $ARGOCD_USER_ID argocd && \
    useradd -r -u $ARGOCD_USER_ID -g argocd argocd && \
    mkdir -p /home/argocd && \
    chown argocd:0 /home/argocd && \
    chmod g=u /home/argocd && \
    apt-get update && \
    apt-get dist-upgrade -y && \
    apt-get install -y \
    git tini gpg tzdata && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

COPY hack/gpg-wrapper.sh /usr/local/bin/gpg-wrapper.sh
COPY hack/git-verify-wrapper.sh /usr/local/bin/git-verify-wrapper.sh
COPY --from=builder /usr/local/bin/helm /usr/local/bin/helm
COPY --from=builder /usr/local/bin/kustomize /usr/local/bin/kustomize
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
# keep uid_entrypoint.sh for backward compatibility
RUN ln -s /usr/local/bin/entrypoint.sh /usr/local/bin/uid_entrypoint.sh

# support for mounting configuration from a configmap
WORKDIR /app/config/ssh
RUN touch ssh_known_hosts && \
    ln -s /app/config/ssh/ssh_known_hosts /etc/ssh/ssh_known_hosts

WORKDIR /app/config
RUN mkdir -p tls && \
    mkdir -p gpg/source && \
    mkdir -p gpg/keys && \
    chown argocd gpg/keys && \
    chmod 0700 gpg/keys

ENV USER=argocd

USER $ARGOCD_USER_ID
WORKDIR /home/argocd

####################################################################################################
# Argo CD UI stage
####################################################################################################
FROM docker.io/library/node:18.15.0@sha256:8d9a875ee427897ef245302e31e2319385b092f1c3368b497e89790f240368f5 AS argocd-ui

WORKDIR /src
COPY ["ui/package.json", "ui/yarn.lock", "./"]

RUN yarn install --network-timeout 200000 && \
    yarn cache clean

COPY ["ui/", "."]

ARG ARGO_VERSION=latest
ENV ARGO_VERSION=$ARGO_VERSION
ARG TARGETARCH
RUN HOST_ARCH=$TARGETARCH NODE_ENV='production' NODE_ONLINE_ENV='online' NODE_OPTIONS=--max_old_space_size=8192 yarn build

####################################################################################################
# Argo CD Build stage which performs the actual build of Argo CD binaries
####################################################################################################
FROM docker.io/library/golang:1.19.9@sha256:9613596d7405705447f36440a59a3a2a1d22384c7568ae1838d0129964c5ba13 AS argocd-build

WORKDIR /go/src/github.com/argoproj/argo-cd

COPY go.* ./
RUN go mod download

# Perform the build
COPY . .
COPY --from=argocd-ui /src/dist/app /go/src/github.com/argoproj/argo-cd/ui/dist/app
ARG TARGETOS
ARG TARGETARCH
RUN GOOS=$TARGETOS GOARCH=$TARGETARCH make argocd-all

####################################################################################################
# Final image
####################################################################################################
FROM argocd-base as argocd

FROM amazon/aws-cli:2.11.19 as awscli

FROM registry1.dso.mil/ironbank/redhat/ubi/ubi8:8.7

ENV HOME=/home/argocd \
    USER=argocd

RUN groupadd -g 1000 argocd && \
    useradd -r -u 1000 -m -s /sbin/nologin -g argocd argocd && \
    chown argocd:argocd ${HOME} && \
    chmod g=u ${HOME} && \
    dnf update -y && \
    dnf install --nodocs -y git git-lfs nss_wrapper && \
    dnf clean all && \
    rm -rf /var/cache/dnf

COPY --from=argocd --chown=root:root /usr/local/bin/argocd /usr/local/bin/
COPY --from=argocd --chown=root:root /usr/local/bin/helm* /usr/local/bin/
COPY --from=argocd --chown=root:root /usr/local/bin/kustomize /usr/local/bin/kustomize
COPY --from=argocd --chown=root:root /usr/bin/tini /usr/bin/tini
COPY --from=awscli --chown=root:root /usr/local/aws-cli /usr/local/aws-cli
COPY scripts/* /usr/local/bin/

RUN mkdir -p /app/config/ssh /app/config/tls && \
    mkdir -p /app/config/gpg/{source,keys} && \
    chown argocd:0 /app/config/gpg/keys && \
    chmod 0700 /app/config/gpg/keys && \
    chmod 0755 /usr/local/bin/*.sh && \
    touch /app/config/ssh/ssh_known_hosts && \
    ln -s /app/config/ssh/ssh_known_hosts /etc/ssh/ssh_known_hosts && \
    ln -s /usr/local/aws-cli/v2/current/bin/aws /usr/local/bin/aws && \
    ln -s /usr/local/aws-cli/v2/current/bin/aws_completer /usr/local/bin/aws_completer && \
    ln -s /usr/local/bin/argocd /usr/local/bin/argocd-server && \
    ln -s /usr/local/bin/argocd /usr/local/bin/argocd-repo-server && \
    ln -s /usr/local/bin/argocd /usr/local/bin/argocd-application-controller && \
    ln -s /usr/local/bin/argocd /usr/local/bin/argocd-dex && \
    ln -s /usr/local/bin/argocd /usr/local/bin/argocd-cmp-server && \
    ln -s /usr/local/bin/argocd /usr/local/bin/argocd-notifications && \
    ln -s /usr/local/bin/argocd /usr/local/bin/argocd-applicationset-controller && \
    ln -s /usr/local/bin/entrypoint.sh /usr/local/bin/uid_entrypoint.sh && \
    chmod -s /usr/libexec/openssh/ssh-keysign

RUN chmod 750 -R /home/argocd

USER 1000
WORKDIR ${HOME}

HEALTHCHECK --start-period=3s \
  CMD curl -f http://localhost:8080/healthz || exit 1

ENTRYPOINT ["entrypoint.sh"]
CMD ["argocd-server"]
