FROM golang:1.23-alpine AS build

WORKDIR /src
COPY backend/ ./
RUN go mod tidy
RUN go build -o /out/archivon-api ./cmd/api

FROM alpine:3.20

RUN adduser -D -H -u 10001 archivon

COPY --from=build /out/archivon-api /usr/local/bin/archivon-api
COPY migrations/ /opt/archivon/migrations/

USER archivon

EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/archivon-api"]
