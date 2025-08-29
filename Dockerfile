FROM rust:1.88-alpine3.22 AS builder

# Install build dependencies with pinned versions
RUN apk add --no-cache musl-dev=1.2.5-r10 openssl-dev=3.5.2-r0

WORKDIR /app

# Copy manifest and source files
COPY . .

# Build the application
RUN cargo build --release

FROM alpine:3.22

# Install required runtime dependencies with pinned versions
RUN apk add --no-cache libgcc=14.2.0-r6

# Set working directory
WORKDIR /app

# Copy the binary from builder stage
COPY --from=builder /app/target/release/tee-worker-post-compute .

# Run the application
ENTRYPOINT ["/app/tee-worker-post-compute"]
