# Use specific versioned base image with digest
FROM alpine:3.19.0@sha256:6457d53fb065d6f250e1504b9bc42d5b6c65941d57532c072d929dd0628977d0 as builder

RUN apk add --no-cache postgresql

# Use specific versioned base image for runtime
FROM alpine:3.19.0@sha256:6457d53fb065d6f250e1504b9bc42d5b6c65941d57532c072d929dd0628977d0

# Add OCI labels for metadata and security
LABEL org.opencontainers.image.title="pgbench" \
      org.opencontainers.image.description="PostgreSQL pgbench benchmarking tool" \
      org.opencontainers.image.version="1.0.0" \
      org.opencontainers.image.source="https://github.com/mattdevdba/docker-pgbench"

# Install runtime dependencies
RUN apk add --no-cache libpq

# Create non-root user
RUN adduser -D -u 1000 pgbench

# Copy binary from builder
COPY --from=builder /usr/bin/pgbench /usr/bin/pgbench

# Switch to non-root user
USER pgbench

# Add health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD pgbench --version || exit 1

CMD ["pgbench"]