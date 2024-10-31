# Use Debian 12 as the base image
FROM debian:12

# Install system dependencies, Tor, and Rust
RUN apt-get update && apt-get install -y \
    curl \
    build-essential \
    git \
    tor \
    && curl https://sh.rustup.rs -sSf | sh -s -- -y \
    && rm -rf /var/lib/apt/lists/*

# Add Rust to PATH
ENV PATH="/root/.cargo/bin:${PATH}"

# Set the working directory
WORKDIR /app

# Clone the repository
RUN git clone https://github.com/umutcamliyurt/Amnesichat.git .

# Build the Rust project in release mode
RUN cargo build --release

# Expose port 8080 for the application
EXPOSE 8080

# Configure Tor hidden service
RUN mkdir -p /var/lib/tor/hidden_service && \
    echo "HiddenServiceDir /var/lib/tor/hidden_service" >> /etc/tor/torrc && \
    echo "HiddenServicePort 80 127.0.0.1:8080" >> /etc/tor/torrc && \
    chown -R debian-tor:debian-tor /var/lib/tor/hidden_service && \
    chmod 700 /var/lib/tor/hidden_service

# Start Tor and the application
CMD service tor start && sleep 5 && cat /var/lib/tor/hidden_service/hostname && cargo run --release
