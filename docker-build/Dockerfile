FROM debian:bookworm

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    pkg-config \
    libssl-dev \
    python3 \
    python3-pip \
    python3-venv \
    && rm -rf /var/lib/apt/lists/*

# Install Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

# Install maturin and pytest
RUN pip3 install --break-system-packages maturin pytest pytest-asyncio

# Create FreeSWITCH lib directory
RUN mkdir -p /usr/local/freeswitch/lib /usr/local/freeswitch/include

WORKDIR /app
