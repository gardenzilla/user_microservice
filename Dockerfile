# FROM rust:1.31 as builder
# WORKDIR /usr/src/myapp
# COPY . .
# RUN cargo build --release

# FROM debian:buster-slim
# # RUN apt-get update && apt-get install -y extra-runtime-dependencies && rm -rf /var/lib/apt/lists/*
# RUN apt-get update && apt-get install -y extra-runtime-dependencies
# COPY --from=builder /usr/local/cargo/bin/myapp /usr/local/bin/myapp
# CMD ["myapp"]

FROM debian:buster-slim
WORKDIR /usr/local/bin
# RUN strip ./target/release/user_microservice
COPY ./target/release/user_microservice /usr/local/bin/user_microservice
RUN apt-get update && apt-get install -y
RUN apt-get install curl -y
CMD ["user_microservice"]
EXPOSE 50051/tcp

# FROM alpine:latest
# WORKDIR /usr/src/app
# # RUN strip ./target/release/user_microservice
# COPY ./target/x86_64-unknown-linux-musl/release/user_microservice /usr/local/bin/user_microservice
# RUN apk -U upgrade
# RUN apk --no-cache add curl
# RUN apk add build-base
# # RUN apk add --no-cache \
# #     perl \  
# #     wget \
# #     openssl \
# #     ca-certificates \
# #     libc6-compat \
# #     libstdc++ \
# #     ENV PATH "$PATH:/usr/local/bin/user_microservice"
# CMD ["user_microservice"]
# EXPOSE 50051/tcp