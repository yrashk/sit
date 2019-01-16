FROM rust:1.31
RUN apt-get update && apt-get install -y cmake libgit2-dev musl-tools
RUN rustup target add x86_64-unknown-linux-musl
RUN apt-get install -y clang libclang-dev
RUN cargo install bindgen
RUN rustup component add rustfmt-preview
# OpenSSL
RUN apt-get update && apt-get install -y build-essential pkg-config libz-dev
RUN curl https://www.openssl.org/source/openssl-1.0.2o.tar.gz | tar xzf - && \
    (cd openssl-1.0.2o && \
          CC=musl-gcc ./Configure --prefix=/openssl-musl no-dso no-ssl2 no-ssl3 linux-x86_64 -fPIC && \
          make -j$(nproc) && \
          make install && cd .. && rm -rf openssl-1.0.2o)
ENV OPENSSL_DIR /openssl-musl
