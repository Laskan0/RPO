# syntax=docker/dockerfile:1

FROM golang:1.26-bookworm AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -o /out/transport_api ./cmd/api


FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends nginx ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /out/transport_api /app/transport_api

COPY migrations /app/migrations
COPY docs /app/docs
COPY nginx/nginx.conf /etc/nginx/nginx.conf
COPY nginx/certs /etc/nginx/certs
COPY docker-entrypoint.sh /app/docker-entrypoint.sh

RUN mkdir -p /app/data \
    && chmod +x /app/docker-entrypoint.sh

ENV APP_ADDR=:8080
ENV DB_PATH=/app/data/transport.db
ENV JWT_SECRET=dev-secret-change-me
ENV ADMIN_USERNAME=admin
ENV ADMIN_PASSWORD=admin123

EXPOSE 8888

CMD ["/app/docker-entrypoint.sh"]
