# Build stage
FROM golang:alpine AS builder

WORKDIR /app

# Initialize modules if needed, or just copy files
COPY go.mod ./
COPY main.go ./

# Build the executable
RUN CGO_ENABLED=0 GOOS=linux go build -o proxy_server .

# Final stage
FROM alpine:latest

# Install tzdata just in case timestamps need specific timezones
RUN apk --no-cache add tzdata

WORKDIR /app
COPY --from=builder /app/proxy_server .

# Create a directory for persistent data (config.json, activity.log)
RUN mkdir /app/data
WORKDIR /app/data

EXPOSE 1080

CMD ["/app/proxy_server"]
