FROM debian:buster-slim
WORKDIR /usr/local/bin
COPY ./target/release/user_microservice /usr/local/bin/user_microservice
RUN apt-get update && apt-get install -y
RUN apt-get install curl -y
STOPSIGNAL SIGINT
ENTRYPOINT ["user_microservice"]