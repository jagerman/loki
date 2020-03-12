# Multistage docker build, requires docker 17.05

# builder stage
FROM ubuntu:16.04 as builder

RUN set -ex && \
    apt-get update && \
    apt-get --no-install-recommends --yes install \
        ca-certificates \
        cmake \
        g++ \
        make \
        pkg-config \
        graphviz \
        doxygen \
        git \
        curl \
        libtool-bin \
        autoconf \
        automake \
        bzip2 \
        xsltproc \
        gperf \
        unzip

WORKDIR /usr/local

ENV CFLAGS='-fPIC'
ENV CXXFLAGS='-fPIC'

#Cmake
ARG CMAKE_VERSION=3.14.0
ARG CMAKE_VERSION_DOT=v3.14
ARG CMAKE_HASH=aa76ba67b3c2af1946701f847073f4652af5cbd9f141f221c97af99127e75502
RUN set -ex \
    && curl -s -O https://cmake.org/files/${CMAKE_VERSION_DOT}/cmake-${CMAKE_VERSION}.tar.gz \
    && echo "${CMAKE_HASH}  cmake-${CMAKE_VERSION}.tar.gz" | sha256sum -c \
    && tar -xzf cmake-${CMAKE_VERSION}.tar.gz \
    && cd cmake-${CMAKE_VERSION} \
    && ./configure \
    && make \
    && make install

## Boost
ARG BOOST_VERSION=1_69_0
ARG BOOST_VERSION_DOT=1.69.0
ARG BOOST_HASH=8f32d4617390d1c2d16f26a27ab60d97807b35440d45891fa340fc2648b04406
RUN set -ex \
    && curl -s -L -o  boost_${BOOST_VERSION}.tar.bz2 https://dl.bintray.com/boostorg/release/${BOOST_VERSION_DOT}/source/boost_${BOOST_VERSION}.tar.bz2 \
    && echo "${BOOST_HASH}  boost_${BOOST_VERSION}.tar.bz2" | sha256sum -c \
    && tar -xvf boost_${BOOST_VERSION}.tar.bz2 \
    && cd boost_${BOOST_VERSION} \
    && ./bootstrap.sh \
    && ./b2 --prefix=/usr/ --build-type=minimal link=static runtime-link=static --with-atomic --with-chrono --with-date_time --with-filesystem --with-program_options --with-regex --with-serialization --with-system --with-thread --with-locale threading=multi threadapi=pthread cflags="$CFLAGS" cxxflags="$CXXFLAGS" install
ENV BOOST_ROOT /usr

# OpenSSL
ARG OPENSSL_VERSION=1.1.1b
ARG OPENSSL_HASH=5c557b023230413dfb0756f3137a13e6d726838ccd1430888ad15bfb2b43ea4b
RUN set -ex \
    && curl -s -O https://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz \
    && echo "${OPENSSL_HASH}  openssl-${OPENSSL_VERSION}.tar.gz" | sha256sum -c \
    && tar -xzf openssl-${OPENSSL_VERSION}.tar.gz \
    && cd openssl-${OPENSSL_VERSION} \
    && ./Configure --prefix=/usr/ linux-x86_64 no-shared --static "$CFLAGS" \
    && make build_generated \
    && make libcrypto.a \
    && make install
ENV OPENSSL_ROOT_DIR=/usr

ARG SODIUM_VERSION=1.0.18-RELEASE
ARG SODIUM_HASH=940ef42797baa0278df6b7fd9e67c7590f87744b
RUN set -ex \
    && git clone https://github.com/jedisct1/libsodium.git -b ${SODIUM_VERSION} --depth=1 \
    && cd libsodium \
    && test `git rev-parse HEAD` = ${SODIUM_HASH} || exit 1 \
    && ./autogen.sh \
    && ./configure --enable-static --disable-shared \
    && make \
    && make check \
    && make install

ARG ZMQ_VERSION=v4.3.2
ARG ZMQ_HASH=a84ffa12b2eb3569ced199660bac5ad128bff1f0
RUN set -ex \
    && git clone https://github.com/zeromq/libzmq.git -b ${ZMQ_VERSION} --depth=1 \
    && cd libzmq \
    && test `git rev-parse HEAD` = ${ZMQ_HASH} || exit 1 \
    && ./autogen.sh \
    && ./configure --prefix=/usr/ --with-libsodium --enable-static --disable-shared \
    && make \
    && make install \
    && ldconfig

# Readline
# ARG READLINE_VERSION=8.0
# ARG READLINE_HASH=e339f51971478d369f8a053a330a190781acb9864cf4c541060f12078948e461
# RUN set -ex \
#     && curl -s -O https://ftp.gnu.org/gnu/readline/readline-${READLINE_VERSION}.tar.gz \
#     && echo "${READLINE_HASH}  readline-${READLINE_VERSION}.tar.gz" | sha256sum -c \
#     && tar -xzf readline-${READLINE_VERSION}.tar.gz \
#     && cd readline-${READLINE_VERSION} \
#     && ./configure \
#     && make \
#     && make install

# Udev
# ARG UDEV_VERSION=v3.2.7
# ARG UDEV_HASH=4758e346a14126fc3a964de5831e411c27ebe487
# RUN set -ex \
#     && git clone https://github.com/gentoo/eudev -b ${UDEV_VERSION} \
#     && cd eudev \
#     && test `git rev-parse HEAD` = ${UDEV_HASH} || exit 1 \
#     && ./autogen.sh \
#     && ./configure --disable-gudev --disable-introspection --disable-hwdb --disable-manpages --disable-shared \
#     && make \
#     && make install

# Sqlite3
ARG SQLITE_VERSION=3310100
ARG SQLITE_HASH=62284efebc05a76f909c580ffa5c008a7d22a1287285d68b7825a2b6b51949ae
RUN set -ex \
    && curl -s -O https://sqlite.org/2020/sqlite-autoconf-${SQLITE_VERSION}.tar.gz \
    && echo "${SQLITE_HASH}  sqlite-autoconf-${SQLITE_VERSION}.tar.gz" | sha256sum -c \
    && tar -xzf sqlite-autoconf-${SQLITE_VERSION}.tar.gz \
    && cd sqlite-autoconf-${SQLITE_VERSION} \
    && ./configure --disable-shared \
    && make \
    && make install

WORKDIR /src
COPY . .

ENV USE_SINGLE_BUILDDIR=1
ARG NPROC
RUN set -ex && \
    git submodule init && git submodule update && \
    rm -rf build && \
    if [ -z "$NPROC" ] ; \
    then make -j$(nproc) release-static ; \
    else make -j$NPROC release-static ; \
    fi

# runtime stage
FROM ubuntu:16.04

RUN set -ex && \
    apt-get update && \
    apt-get --no-install-recommends --yes install ca-certificates && \
    apt-get clean && \
    rm -rf /var/lib/apt
COPY --from=builder /src/build/release/bin /usr/local/bin/

# Create loki user
RUN adduser --system --group --disabled-password loki && \
	mkdir -p /wallet /home/loki/.loki && \
	chown -R loki:loki /home/loki/.loki && \
	chown -R loki:loki /wallet

# Contains the blockchain
VOLUME /home/loki/.loki

# Generate your wallet via accessing the container and run:
# cd /wallet
# loki-wallet-cli
VOLUME /wallet

EXPOSE 22022
EXPOSE 22023

# switch to user monero
USER loki

ENTRYPOINT ["lokid", "--p2p-bind-ip=0.0.0.0", "--p2p-bind-port=22022", "--rpc-bind-ip=0.0.0.0", "--rpc-bind-port=22023", "--non-interactive", "--confirm-external-bind"]

