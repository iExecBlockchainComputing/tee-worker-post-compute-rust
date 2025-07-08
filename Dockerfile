FROM rust:1.86-alpine3.21 AS builder

RUN apk add --no-cache musl-dev openssl-dev

WORKDIR /app

COPY . /app

RUN cargo build --release

FROM alpine:3.21

WORKDIR /app

RUN apk add --no-cache libgcc

COPY --from=builder /app/target/release/tee-worker-post-compute .

CMD ["/app/tee-worker-post-compute"]
