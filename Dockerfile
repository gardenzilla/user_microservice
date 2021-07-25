FROM fedora:34
RUN dnf update -y && dnf clean all -y
WORKDIR /usr/local/bin
COPY ./target/release/user_microservice /usr/local/bin/user_microservice
STOPSIGNAL SIGINT
ENTRYPOINT ["user_microservice"]
