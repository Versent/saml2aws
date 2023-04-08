FROM golang:1.20-bullseye as build-env

WORKDIR /go/src/app
ADD . /go/src/app

RUN apt-get update && apt-get install -y libudev-dev

RUN go install ./cmd/saml2aws

FROM gcr.io/distroless/base

COPY --from=build-env /go/bin/saml2aws /
COPY --from=build-env /usr/lib/x86_64-linux-gnu/libudev.so.1 /usr/lib/x86_64-linux-gnu/libudev.so.1

CMD ["/saml2aws"]