# Build pyswitch with FreeSWITCH (dynamic linking)
#
# Multi-stage build:
# 1. Build FreeSWITCH shared library
# 2. Build pyswitch Rust module with dynamic linking
#
# Usage:
#   docker build -t pyswitch .
#   docker run --rm pyswitch

# =============================================================================
# Stage 1: Build FreeSWITCH shared library
# =============================================================================
FROM python:3.11-slim-bookworm AS freeswitch-builder

# Install FreeSWITCH build dependencies
RUN apt-get update && apt-get install -y \
    git \
    build-essential \
    autoconf \
    automake \
    libtool \
    libtool-bin \
    pkg-config \
    libssl-dev \
    libpcre3-dev \
    libspeex-dev \
    libspeexdsp-dev \
    libedit-dev \
    libsqlite3-dev \
    libcurl4-openssl-dev \
    libldns-dev \
    uuid-dev \
    zlib1g-dev \
    libjpeg-dev \
    libpng-dev \
    libtiff-dev \
    libsndfile1-dev \
    wget \
    && rm -rf /var/lib/apt/lists/*

ENV PKG_CONFIG_PATH=/usr/local/freeswitch/lib/pkgconfig
ENV LD_LIBRARY_PATH=/usr/local/freeswitch/lib
ENV CFLAGS="-I/usr/local/freeswitch/include"
ENV LDFLAGS="-L/usr/local/freeswitch/lib"

WORKDIR /build

# Build spandsp 3.0 from source (required by FreeSWITCH 1.10.12)
RUN git clone --depth 1 https://github.com/freeswitch/spandsp.git spandsp && \
    cd spandsp && \
    ./bootstrap.sh && \
    ./configure --prefix=/usr/local/freeswitch && \
    make -j$(nproc) && \
    make install && \
    ldconfig

# Build sofia-sip 1.13.17 from source (required by mod_sofia)
RUN git clone --depth 1 --branch v1.13.17 https://github.com/freeswitch/sofia-sip.git sofia-sip && \
    cd sofia-sip && \
    ./bootstrap.sh && \
    ./configure --prefix=/usr/local/freeswitch && \
    make -j$(nproc) && \
    make install && \
    ldconfig

# Ensure pkg-config can find the libraries
RUN echo "/usr/local/freeswitch/lib" > /etc/ld.so.conf.d/freeswitch.conf && ldconfig

# Clone FreeSWITCH 1.10.12
RUN git clone --depth 1 --branch v1.10.12 \
    https://github.com/signalwire/freeswitch.git freeswitch

WORKDIR /build/freeswitch

# Create minimal modules.conf - just SIP endpoint
RUN echo 'endpoints/mod_sofia' > modules.conf

# Bootstrap and configure (SHARED library, not static)
RUN ./bootstrap.sh -j && \
    ./configure \
        --prefix=/usr/local/freeswitch \
        --disable-debug \
        --disable-libyuv \
        --disable-libvpx \
        --without-python \
        --without-java \
        --without-lua \
        --without-perl \
        --without-erlang \
        PKG_CONFIG_PATH=/usr/local/freeswitch/lib/pkgconfig

# Build (this takes a while)
RUN make -j$(nproc) && make install

# =============================================================================
# Stage 2: Build pyswitch with dynamic FreeSWITCH linking
# =============================================================================

FROM python:3.11-slim-bookworm AS pyswitch-builder

# Install Rust and maturin + FreeSWITCH runtime dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    pkg-config \
    libssl-dev \
    uuid-dev \
    libpcre3-dev \
    libedit-dev \
    libcurl4-openssl-dev \
    libsqlite3-dev \
    libspeex-dev \
    libspeexdsp-dev \
    zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

RUN pip install maturin patchelf

# Copy FreeSWITCH shared libraries from builder
COPY --from=freeswitch-builder /usr/local/freeswitch /usr/local/freeswitch

# Set up library paths
RUN ln -sf /usr/local/freeswitch/lib/libfreeswitch.so /usr/lib/ && \
    ln -sf /usr/local/freeswitch/lib/libfreeswitch.so.1 /usr/lib/ && \
    ln -sf /usr/local/freeswitch/lib/libsofia-sip-ua.so /usr/lib/ && \
    ln -sf /usr/local/freeswitch/lib/libsofia-sip-ua.so.0 /usr/lib/ && \
    ln -sf /usr/local/freeswitch/lib/libspandsp.so /usr/lib/ && \
    ln -sf /usr/local/freeswitch/lib/libspandsp.so.3 /usr/lib/ && \
    ldconfig

# Set environment for DYNAMIC linking
ENV FREESWITCH_DYNAMIC=1
ENV FREESWITCH_LIB_DIR=/usr/local/freeswitch/lib
ENV FREESWITCH_INCLUDE_DIR=/usr/local/freeswitch/include/freeswitch
ENV LD_LIBRARY_PATH=/usr/local/freeswitch/lib

WORKDIR /app

# Copy source code
COPY . .

# Build the module with dynamic linking
RUN maturin build --release && \
    pip install $(ls target/wheels/rtp_sip-*.whl | head -1)

# Install pytest for Python tests
RUN pip install pytest pytest-asyncio

# =============================================================================
# Stage 3: Final runtime image
# =============================================================================

FROM python:3.11-slim-bookworm

# Install runtime dependencies only
RUN apt-get update && apt-get install -y \
    libssl3 \
    libpcre3 \
    libedit2 \
    libcurl4 \
    libsqlite3-0 \
    libspeex1 \
    libspeexdsp1 \
    zlib1g \
    libuuid1 \
    libtiff6 \
    libjpeg62-turbo \
    libpng16-16 \
    && rm -rf /var/lib/apt/lists/*

# Copy FreeSWITCH shared libraries
COPY --from=freeswitch-builder /usr/local/freeswitch /usr/local/freeswitch

# Set up library paths
RUN ln -sf /usr/local/freeswitch/lib/libfreeswitch.so /usr/lib/ && \
    ln -sf /usr/local/freeswitch/lib/libfreeswitch.so.1 /usr/lib/ && \
    ln -sf /usr/local/freeswitch/lib/libsofia-sip-ua.so /usr/lib/ && \
    ln -sf /usr/local/freeswitch/lib/libsofia-sip-ua.so.0 /usr/lib/ && \
    ln -sf /usr/local/freeswitch/lib/libspandsp.so /usr/lib/ && \
    ln -sf /usr/local/freeswitch/lib/libspandsp.so.3 /usr/lib/ && \
    ldconfig

ENV LD_LIBRARY_PATH=/usr/local/freeswitch/lib

# Copy the built wheel and install
COPY --from=pyswitch-builder /app/target/wheels/*.whl /tmp/
RUN pip install $(ls /tmp/rtp_sip-*.whl | head -1) && rm /tmp/*.whl

# =============================================================================
# FreeSWITCH Runtime Configuration
# =============================================================================

# Create FreeSWITCH directory structure (standard prefix paths)
RUN mkdir -p /usr/local/freeswitch/etc/freeswitch \
             /usr/local/freeswitch/var/log/freeswitch \
             /usr/local/freeswitch/var/run/freeswitch \
             /usr/local/freeswitch/var/lib/freeswitch/db \
             /usr/local/freeswitch/share/freeswitch/scripts \
             /usr/local/freeswitch/share/freeswitch/sounds \
             /usr/local/freeswitch/etc/freeswitch/tls

# Copy minimal FreeSWITCH configuration
COPY conf/freeswitch.xml /usr/local/freeswitch/etc/freeswitch/

# Set permissions
RUN chmod -R 755 /usr/local/freeswitch && \
    chmod 644 /usr/local/freeswitch/etc/freeswitch/*.xml

# Verify setup
RUN echo "FreeSWITCH libraries:" && \
    ls -la /usr/local/freeswitch/lib/*.so* | head -10 && \
    echo "Configuration:" && \
    ls -la /usr/local/freeswitch/etc/freeswitch/

# Verify wheel was installed
RUN pip show rtp_sip && echo "rtp_sip wheel installed successfully"

# Install test dependencies
RUN pip install pytest pytest-asyncio

# Copy tests
COPY python/tests /app/tests

WORKDIR /app

# Default command
CMD ["python3", "-c", "import rtp_sip; print('rtp_sip version:', rtp_sip.__version__); print('Available:', dir(rtp_sip))"]
