FROM golang:1.24.2-alpine AS builder

WORKDIR /src
#Нужно чтобы докер кешировал скачивание зависимостей. Дальше качаем зависимости go модуля 
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
#Копируем весь проект в контейнер 
COPY . .

#собирается бинарник сервера 
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/server ./cmd/server
#качаем гуся 
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build GOBIN=/out go install -tags='no_postgres no_clickhouse no_mssql no_mysql no_libsql no_vertica no_ydb' github.com/pressly/goose/v3/cmd/goose@v3.24.1

FROM node:22-alpine AS frontend-builder

WORKDIR /frontend

COPY frontend/package.json ./
COPY frontend/package-lock.json ./
COPY frontend/tsconfig.json ./
COPY frontend/tsconfig.app.json ./
COPY frontend/vite.config.ts ./
COPY frontend/index.html ./
COPY frontend/src ./src

RUN npm install
RUN npm run build

FROM alpine:3.21
#рабочая папка 
WORKDIR /app
#ставим nginx
RUN apk add --no-cache nginx ca-certificates
#копируем бинарник сервера в финальный контейнер 
COPY --from=builder /out/server /app/server
#то же самое с гусем
COPY --from=builder /out/goose /usr/local/bin/goose

COPY migrations /app/migrations
COPY docs /app/docs
COPY nginx/default.conf /etc/nginx/http.d/default.conf
COPY certs /app/certs
COPY scripts/entrypoint.sh /app/entrypoint.sh
COPY --from=frontend-builder /frontend/dist /usr/share/nginx/html
#выделяются права на запуск сервера и энтрипоинт и создается папка nginx
RUN chmod +x /app/server /app/entrypoint.sh && \
    mkdir -p /run/nginx /usr/share/nginx/html

ENV APP_HOST=127.0.0.1
ENV APP_PORT=8080
ENV APP_DATABASE_PATH=/app/transport.db
ENV APP_JWT_SECRET=very-secret-key

EXPOSE 8888

CMD ["/app/entrypoint.sh"]
