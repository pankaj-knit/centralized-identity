FROM golang:1.22-alpine AS builder

WORKDIR /app
COPY . .
RUN go mod tidy && CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /token-exchange ./cmd/server

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /token-exchange /token-exchange

EXPOSE 8080
USER nonroot:nonroot

ENTRYPOINT ["/token-exchange"]
