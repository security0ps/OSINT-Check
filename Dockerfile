# Für neue Go-Sicherheitsupdates das Image regelmäßig neu bauen: docker compose build --pull
FROM golang:1.27-alpine AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go test ./... && CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags "-s -w" -o /osint-check .

FROM alpine:3.24
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
RUN adduser -D -H osint && mkdir -m 0700 /data && chown osint /data
COPY --from=build /osint-check /usr/local/bin/osint-check
USER osint
ENTRYPOINT ["osint-check"]
