FROM golang:1.24.1 AS builder
WORKDIR /app
COPY ../go.mod go.sum ./
RUN go mod download
COPY .. .
RUN CGO_ENABLED=0 go build -o auth ./cmd/auth

FROM gcr.io/distroless/base-debian12
WORKDIR /app
COPY --from=builder /app/auth /app/auth
COPY ../configs/config.json /app/config.json
COPY ../keys /app/keys
EXPOSE 8080 50051
ENTRYPOINT ["/app/auth"]
