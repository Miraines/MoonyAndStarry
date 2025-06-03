FROM golang:1.22 AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o auth ./cmd/auth

FROM gcr.io/distroless/base-debian12
WORKDIR /app
COPY --from=builder /app/auth /app/auth
COPY config.json /app/config.json
COPY keys /app/keys
EXPOSE 8080 50051
ENTRYPOINT ["/app/auth"]
