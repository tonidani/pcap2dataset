FROM python:3.11-slim

# Install system dependencies and tshark (for capinfos)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        tshark \
        wireshark-common \
        ca-certificates \
        curl \
        gnupg && \
    rm -rf /var/lib/apt/lists/*

# Install Python packages
RUN pip install --no-cache-dir scapy pandas pyarrow

# Set working directory
WORKDIR /app

# Encoding settings
ENV PYTHONIOENCODING=UTF-8

# Default entry
CMD ["bash"]
