FROM rust:1.31
RUN apt-get update && apt-get install -y clang autotools-dev automake cmake libfuse-dev fuse git
RUN rustup target add x86_64-apple-darwin
RUN git clone https://github.com/tpoechtrager/osxcross && cd osxcross && git checkout 1a1733a
COPY MacOSX10.11.sdk.tar.xz /osxcross/tarballs/
RUN cd osxcross && UNATTENDED=1 OSX_VERSION_MIN=10.7 ./build.sh
ENV PATH="/osxcross/target/bin:$PATH"
ENV CARGO_TARGET_X86_64_APPLE_DARWIN_LINKER x86_64-apple-darwin15-clang
ENV CC_X86_64_APPLE_DARWIN_LINKER x86_64-apple-darwin15-clang
ENV CMAKE_C_LINK_EXECUTABLE x86_64-apple-darwin15-ld
ENV CMAKE_C_COMPILER_EXTERNAL_TOOLCHAIN x86_64-apple-darwin15-cc
ENV CMAKE_C_COMPILER x86_64-apple-darwin15-cc
# OpenSSL
ENV PKG_CONFIG_ALLOW_CROSS 1
RUN curl https://www.openssl.org/source/openssl-1.0.2o.tar.gz | tar xzf - && \
    (cd openssl-1.0.2o && \
          CC=x86_64-apple-darwin15-cc AR=x86_64-apple-darwin15-ar \
          RANLIB=x86_64-apple-darwin15-ranlib \
          ./Configure --prefix=/openssl no-dso no-ssl2 no-ssl3 darwin64-x86_64-cc -fPIC && \
          make -j$(nproc) && \
          make install && cd .. && rm -rf openssl-1.0.2o)
ENV OPENSSL_DIR /openssl
RUN curl https://curl.haxx.se/download/curl-7.61.0.tar.bz2 | tar xjf - && \
    (cd curl-7.61.0 && \
       ./configure --prefix=/curl --host x86_64-apple-darwin15 --with-ssl=/openssl && make && make install && \
       cd .. && rm -rf curl-7.61.0)
ENV DEP_CURL_ROOT /curl
ENV CROSS_COMPILE x86_64-apple-darwin15-
COPY x86_64-apple-darwin15-gcc /osxcross/target/bin/x86_64-apple-darwin15-gcc
RUN chmod +x /osxcross/target/bin/x86_64-apple-darwin15-gcc
