# Build stage
FROM golang:1.21-alpine AS builder

# Install security updates and build dependencies
RUN apk update && apk add --no-cache \
    git \
    ca-certificates \
    tzdata \
    gcc \
    musl-dev \
    && rm -rf /var/cache/apk/*

# Create non-root user for building
RUN adduser -D -s /bin/sh builder

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download && go mod verify

# Copy source code
COPY . .

# Build the binary with security flags
RUN CGO_ENABLED=1 GOOS=linux go build \
    -ldflags='-w -s -extldflags "-static"' \
    -a -installsuffix cgo \
    -o ghostkey-server .

# Production stage
FROM alpine:latest

# Install runtime dependencies and security updates
RUN apk update && apk add --no-cache \
    ca-certificates \
    tzdata \
    wget \
    && rm -rf /var/cache/apk/*

# Create non-root user
RUN adduser -D -s /bin/sh ghostkey

# Create directories
RUN mkdir -p /app/cargo_files && \
    chown -R ghostkey:ghostkey /app

# Copy the binary
COPY --from=builder /app/ghostkey-server /app/ghostkey-server

# Copy configuration files
COPY config.json /app/config.json

# Set permissions
RUN chmod +x /app/ghostkey-server

# Switch to non-root user
USER ghostkey

# Set working directory
WORKDIR /app

# Expose port
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:5000/health || exit 1

# Set environment variables
ENV GIN_MODE=release
ENV SECRET_KEY=""

# Run the binary
CMD ["./ghostkey-server"]
