# Für neue Go-Sicherheitsupdates das Image regelmäßig neu bauen: docker compose build --pull
FROM golang:1.27-alpine AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go test ./... && CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags "-s -w" -o /osint-check .

FROM alpine:3.24
RUN apk add --no-cache ca-certificates && adduser -D -H osint
COPY --from=build /osint-check /usr/local/bin/osint-check
USER osint
ENTRYPOINT ["osint-check", "--server", "--listen", "0.0.0.0:8484", "--config", "/config/config.json"]
