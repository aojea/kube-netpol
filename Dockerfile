ARG GOARCH="amd64"
# STEP 1: Build kindnetd binary
FROM golang:1.22 AS builder
# golang envs
ARG GOARCH="amd64"
ARG CNI_VERSION="v1.2.0"
ARG GOOS=linux
ENV CGO_ENABLED=0
ENV GO111MODULE="on"
ENV GOPROXY=https://proxy.golang.org
# copy in sources
WORKDIR /src
COPY . .
# build
RUN CGO_ENABLED=0 go build -o /go/bin/kindnetd ./cmd/kindnetd
# STEP 2: Build small image
FROM registry.k8s.io/build-image/distroless-iptables:v0.2.1
COPY --from=builder --chown=root:root /go/bin/kindnetd /bin/kindnetd
COPY --from=builder --chown=root:root /opt/cni/bin /opt/cni/bin
CMD ["/bin/kindnetd"]
