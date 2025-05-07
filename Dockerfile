FROM golang AS builder
ADD src/ /project/
ADD build.sh /project/
RUN cd /project/ && go mod init ssl_handshake && go mod tidy && bash /project/build.sh

FROM scratch AS export-stage
COPY --from=builder /project/binaries .

##CMD to build: DOCKER_BUILDKIT=1 docker build --output binaries .
