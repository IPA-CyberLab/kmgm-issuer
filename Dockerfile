FROM golang:buster as build
WORKDIR /go/src/kmgm-issuer
COPY . /go/src/kmgm-issuer
RUN go get -d ./...
RUN go build -o /go/bin/kmgm-issuer

FROM gcr.io/distroless/base
COPY --from=build /go/bin/kmgm-issuer /
CMD ["/kmgm-issuer"]
