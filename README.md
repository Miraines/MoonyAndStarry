# MoonyAndStarry Auth Service

This repository contains an example authorization service written in Go. The service exposes both HTTP and gRPC APIs for user registration, authentication and token management.

## Usage

1. Ensure a PostgreSQL and Redis instance are running. Docker compose configuration is provided in `auth-service/docker-compose.yml`.
2. Populate environment variables or edit `auth-service/config.json` with the correct settings.
3. Build and run the service:

```bash
go run ./cmd/auth
```

Generated protobuf files are located under `pkg/proto`.

