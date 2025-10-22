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
COPY devcerts/ ./devcerts/

RUN mkdir -p /run/mtls /run/devcerts

ENV LISTEN_ADDR=:8443 \
    APP_ORIGIN=https://recco-tpp.test:8443 \
    REDIRECT_URI=https://recco-tpp.test:8443/api \
    WELL_KNOWN_URL=https://auth.directory.recco.raidiam.io/.well-known/openid-configuration \
    CLIENT_ID=https://rp.directory.recco.raidiam.io/openid_relying_party/1575bb8f-20ef-46ca-ac3f-21dfb35eaa7b \
    PARTICIPANTS_URL=https://data.directory.recco.raidiam.io/participants \
    DEV_TLS_CERT_FILE=/run/devcerts/recco-tpp.test.pem \
    DEV_TLS_KEY_FILE=/run/devcerts/recco-tpp.test-key \
    MTLS_CERT_FILE=/run/mtls/client.pem \
    MTLS_KEY_FILE=/run/mtls/client.key \
    MTLS_CA_FILE=/run/mtls/ca.pem \
    SIGNING_KEY_FILE=/run/mtls/server.key

EXPOSE 8443

CMD [ "/app/tpp-server" ]
