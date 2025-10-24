# Step 1: Build Stage.
FROM golang:1.25-alpine AS builder

WORKDIR /src
RUN apk add --no-cache git ca-certificates

COPY go.mod go.sum ./
RUN go mod download

COPY tpp/ ./tpp/
COPY shared/ ./shared/
COPY web/ ./web/

ENV CGO_ENABLED=0
RUN go build -o /bin/tpp-server ./tpp/cmd/

# Step 2: TPP Service Run Stage.
FROM alpine:latest AS tpp-service

RUN apk add --no-cache ca-certificates tzdata

WORKDIR /app
COPY --from=builder /bin/tpp-server /app/tpp-server
COPY --from=builder /src/web /app/web
COPY certs/ ./certs/
COPY devcerts/recco-tpp.* ./devcerts/

RUN mkdir -p /run/mtls /run/devcerts

ENV APP_ORIGIN=http://localhost:8080 \
    REDIRECT_URI=http://localhost:8080/api \
    WELL_KNOWN_URL=https://auth.directory.recco.raidiam.io/.well-known/openid-configuration \
    CLIENT_ID=<client id goes here> \
    PARTICIPANTS_URL=https://data.directory.recco.raidiam.io/participants \
    DEV_TLS_CERT_FILE=/run/devcerts/recco-tpp.test.pem \
    DEV_TLS_KEY_FILE=/run/devcerts/recco-tpp.test-key \
    MTLS_CERT_FILE=/run/mtls/client.pem \
    MTLS_KEY_FILE=/run/mtls/client.key \
    MTLS_CA_FILE=/run/mtls/ca.pem \
    SIGNING_KEY_FILE=/run/mtls/server.key

EXPOSE 8443 8080

CMD [ "/app/tpp-server" ]
