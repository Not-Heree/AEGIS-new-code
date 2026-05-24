# ========== SINGLE STAGE: Download pre-built tools ==========
FROM python:3.11-slim-bookworm

# System dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap0.8 \
    curl \
    wget \
    git \
    unzip \
    dnsutils \
    ca-certificates \
    whois \
    && rm -rf /var/lib/apt/lists/*

# ── Download Pre-Built ProjectDiscovery Binaries ──────────
# These are official releases from GitHub — no Go needed

# nuclei
RUN wget -q https://github.com/projectdiscovery/nuclei/releases/download/v3.3.7/nuclei_3.3.7_linux_amd64.zip \
    && unzip nuclei_3.3.7_linux_amd64.zip -d /tmp/nuclei \
    && mv /tmp/nuclei/nuclei /usr/local/bin/nuclei \
    && chmod +x /usr/local/bin/nuclei \
    && rm -rf nuclei_3.3.7_linux_amd64.zip /tmp/nuclei

# httpx
RUN wget -q https://github.com/projectdiscovery/httpx/releases/download/v1.6.10/httpx_1.6.10_linux_amd64.zip \
    && unzip httpx_1.6.10_linux_amd64.zip -d /tmp/httpx \
    && mv /tmp/httpx/httpx /usr/local/bin/httpx \
    && chmod +x /usr/local/bin/httpx \
    && rm -rf httpx_1.6.10_linux_amd64.zip /tmp/httpx

# naabu
RUN wget -q https://github.com/projectdiscovery/naabu/releases/download/v2.3.3/naabu_2.3.3_linux_amd64.zip \
    && unzip naabu_2.3.3_linux_amd64.zip -d /tmp/naabu \
    && mv /tmp/naabu/naabu /usr/local/bin/naabu \
    && chmod +x /usr/local/bin/naabu \
    && rm -rf naabu_2.3.3_linux_amd64.zip /tmp/naabu

# subfinder
RUN wget -q https://github.com/projectdiscovery/subfinder/releases/download/v2.6.7/subfinder_2.6.7_linux_amd64.zip \
    && unzip subfinder_2.6.7_linux_amd64.zip -d /tmp/subfinder \
    && mv /tmp/subfinder/subfinder /usr/local/bin/subfinder \
    && chmod +x /usr/local/bin/subfinder \
    && rm -rf subfinder_2.6.7_linux_amd64.zip /tmp/subfinder

# Verify all tools work
RUN nuclei -version && httpx -version && naabu -version && subfinder -version

# Download nuclei templates
RUN nuclei -update-templates

# Install theHarvester
RUN pip install --no-cache-dir theHarvester

# ── Python App Setup ──────────────────────────────────────
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p /app/generated_reports

# Environment defaults
ENV PYTHONUNBUFFERED=1
ENV NUCLEI_PATH=/usr/local/bin/nuclei
ENV HTTPX_PATH=/usr/local/bin/httpx
ENV NAABU_PATH=/usr/local/bin/naabu
ENV SUBFINDER_PATH=/usr/local/bin/subfinder
ENV THEHARVESTER_PATH=theHarvester

EXPOSE 5000

CMD ["python", "app.py"]