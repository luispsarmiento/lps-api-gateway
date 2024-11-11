FROM rust:1.82

WORKDIR /usr/src/app

COPY . .

RUN cargo build --release && rm -r src

CMD ["./target/release/lps-api-gateway"]

EXPOSE 8080