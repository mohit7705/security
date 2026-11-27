
# syntax=docker/dockerfile:1

# ============================================================
# BUILDER STAGE
# ============================================================

FROM python:3.11-slim-bookworm AS builder

WORKDIR /build

# System dependencies required for downloading, building,
# and installing security tools and Playwright.
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    unzip \
    tar \
    ca-certificates \
    git \
    golang-go \
    libatomic1 \
    && rm -rf /var/lib/apt/lists/*

ARG TARGETARCH

ARG NUCLEI_VERSION=3.3.7
ARG SUBFINDER_VERSION=2.6.7
ARG KATANA_VERSION=1.1.0
ARG HTTPX_VERSION=1.6.9
ARG FFUF_VERSION=2.1.0
ARG GAU_VERSION=2.2.4
ARG FEROXBUSTER_VERSION=2.11.0
ARG AMASS_VERSION=4.2.0
ARG TESTSSL_VERSION=v3.2.5
ARG ASSETFINDER_VERSION=v0.1.1
ARG WAYBACKURLS_VERSION=v0.1.0

# ------------------------------------------------------------
# Install ProjectDiscovery tools:
# Nuclei, Subfinder, Katana, HTTPX
# ------------------------------------------------------------

RUN set -eux; \
    case "${TARGETARCH}" in \
      amd64) ARCH="amd64" ;; \
      arm64) ARCH="arm64" ;; \
      *) echo "Unsupported build architecture: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    curl -fsSL "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${ARCH}.zip" -o /tmp/nuclei.zip; \
    unzip -q /tmp/nuclei.zip nuclei -d /usr/local/bin/; \
    curl -fsSL "https://github.com/projectdiscovery/subfinder/releases/download/v${SUBFINDER_VERSION}/subfinder_${SUBFINDER_VERSION}_linux_${ARCH}.zip" -o /tmp/subfinder.zip; \
    unzip -q /tmp/subfinder.zip subfinder -d /usr/local/bin/; \
    curl -fsSL "https://github.com/projectdiscovery/katana/releases/download/v${KATANA_VERSION}/katana_${KATANA_VERSION}_linux_${ARCH}.zip" -o /tmp/katana.zip; \
    unzip -q /tmp/katana.zip katana -d /usr/local/bin/; \
    curl -fsSL "https://github.com/projectdiscovery/httpx/releases/download/v${HTTPX_VERSION}/httpx_${HTTPX_VERSION}_linux_${ARCH}.zip" -o /tmp/httpx.zip; \
    unzip -q /tmp/httpx.zip httpx -d /usr/local/bin/; \
    ln -sf /usr/local/bin/httpx /usr/local/bin/httpx-toolkit; \
    chmod +x /usr/local/bin/nuclei /usr/local/bin/subfinder /usr/local/bin/katana /usr/local/bin/httpx; \
    rm -f /tmp/*.zip

# ------------------------------------------------------------
# Install ffuf, gau, feroxbuster, OWASP Amass
# ------------------------------------------------------------

RUN set -eux; \
    case "${TARGETARCH}" in \
      amd64) GO_ARCH="amd64"; RUST_ARCH="x86_64-linux" ;; \
      arm64) GO_ARCH="arm64"; RUST_ARCH="aarch64-linux" ;; \
      *) echo "Unsupported build architecture: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    curl -fsSL "https://github.com/ffuf/ffuf/releases/download/v${FFUF_VERSION}/ffuf_${FFUF_VERSION}_linux_${GO_ARCH}.tar.gz" -o /tmp/ffuf.tar.gz; \
    tar -xzf /tmp/ffuf.tar.gz -C /usr/local/bin ffuf; \
    curl -fsSL "https://github.com/lc/gau/releases/download/v${GAU_VERSION}/gau_${GAU_VERSION}_linux_${GO_ARCH}.tar.gz" -o /tmp/gau.tar.gz; \
    tar -xzf /tmp/gau.tar.gz -C /usr/local/bin gau; \
    curl -fsSL "https://github.com/epi052/feroxbuster/releases/download/v${FEROXBUSTER_VERSION}/${RUST_ARCH}-feroxbuster.tar.gz" -o /tmp/ferox.tar.gz; \
    tar -xzf /tmp/ferox.tar.gz -C /usr/local/bin feroxbuster; \
    curl -fsSL "https://github.com/owasp-amass/amass/releases/download/v${AMASS_VERSION}/amass_Linux_${GO_ARCH}.zip" -o /tmp/amass.zip; \
    unzip -q -j /tmp/amass.zip "*/amass" -d /usr/local/bin/; \
    chmod +x /usr/local/bin/ffuf /usr/local/bin/gau /usr/local/bin/feroxbuster /usr/local/bin/amass; \
    rm -f /tmp/*.tar.gz /tmp/*.zip

# ------------------------------------------------------------
# Build assetfinder and waybackurls
# ------------------------------------------------------------

RUN set -eux; \
    GOBIN=/usr/local/bin go install "github.com/tomnomnom/assetfinder@${ASSETFINDER_VERSION}"; \
    GOBIN=/usr/local/bin go install "github.com/tomnomnom/waybackurls@${WAYBACKURLS_VERSION}"; \
    rm -rf /root/go /root/.cache/go-build

# ------------------------------------------------------------
# Install pinned testssl.sh release
# ------------------------------------------------------------

RUN set -eux; \
    git clone --depth 1 --branch "${TESTSSL_VERSION}" \
      https://github.com/testssl/testssl.sh.git /opt/testssl; \
    test -f /opt/testssl/testssl.sh; \
    rm -rf /opt/testssl/.git; \
    chmod 0755 /opt/testssl/testssl.sh

# ------------------------------------------------------------
# Install BBOT in an isolated virtual environment
# ------------------------------------------------------------

RUN python -m venv /opt/bbot-venv && \
    /opt/bbot-venv/bin/pip install --no-cache-dir --upgrade pip && \
    /opt/bbot-venv/bin/pip install --no-cache-dir bbot

# ------------------------------------------------------------
# Build Quiver application environment
# ------------------------------------------------------------

RUN python -m venv /opt/venv && \
    mkdir -p /opt/ms-playwright

ENV PATH="/opt/venv/bin:$PATH"

COPY pyproject.toml README.md ./
COPY src/ ./src/
COPY config/ ./config/

ARG INSTALL_BROWSER=false

RUN pip install --no-cache-dir --upgrade pip && \
    if [ "${INSTALL_BROWSER}" = "true" ]; then \
      pip install --no-cache-dir ".[browser,ui]" && \
      PLAYWRIGHT_BROWSERS_PATH=/opt/ms-playwright \
        python -m playwright install chromium; \
    else \
      pip install --no-cache-dir ".[ui]"; \
    fi


# ============================================================
# RUNTIME STAGE
# ============================================================

FROM python:3.11-slim-bookworm AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:/usr/local/bin:$PATH" \
    HOME="/home/scanner" \
    PLAYWRIGHT_BROWSERS_PATH="/opt/ms-playwright"

# Runtime dependencies for security tools and Playwright.
RUN apt-get update && apt-get install -y --no-install-recommends \
    bash \
    libatomic1 \
    ca-certificates \
    dnsutils \
    whois \
    nmap \
    whatweb \
    openssl \
    procps \
    xxd \
    bsdextrautils \
    && rm -rf /var/lib/apt/lists/*

ARG INSTALL_BROWSER=false

# ------------------------------------------------------------
# Create non-root scanner user
# ------------------------------------------------------------

RUN groupadd --gid 1000 scanner && \
    useradd --uid 1000 \
      --gid 1000 \
      --create-home \
      --shell /bin/bash scanner && \
    mkdir -p /app/output /app/secrets /app/config && \
    chown -R scanner:scanner /app /home/scanner

# ------------------------------------------------------------
# Copy application and security tools from builder
# ------------------------------------------------------------

COPY --from=builder /opt/venv /opt/venv
COPY --from=builder /opt/ms-playwright /opt/ms-playwright
COPY --from=builder /opt/bbot-venv /opt/bbot-venv
COPY --from=builder /opt/testssl /opt/testssl

COPY --from=builder /usr/local/bin/nuclei /usr/local/bin/nuclei
COPY --from=builder /usr/local/bin/subfinder /usr/local/bin/subfinder
COPY --from=builder /usr/local/bin/katana /usr/local/bin/katana
COPY --from=builder /usr/local/bin/httpx /usr/local/bin/httpx
COPY --from=builder /usr/local/bin/ffuf /usr/local/bin/ffuf
COPY --from=builder /usr/local/bin/gau /usr/local/bin/gau
COPY --from=builder /usr/local/bin/feroxbuster /usr/local/bin/feroxbuster
COPY --from=builder /usr/local/bin/amass /usr/local/bin/amass
COPY --from=builder /usr/local/bin/assetfinder /usr/local/bin/assetfinder
COPY --from=builder /usr/local/bin/waybackurls /usr/local/bin/waybackurls

COPY --chown=scanner:scanner config/ /app/config/

# ------------------------------------------------------------
# Configure tool aliases and browser dependencies
# ------------------------------------------------------------

RUN ln -sf /usr/local/bin/httpx /usr/local/bin/httpx-toolkit && \
    ln -sf /opt/bbot-venv/bin/bbot /usr/local/bin/bbot && \
    ln -sf /opt/testssl/testssl.sh /usr/local/bin/testssl.sh && \
    if [ "${INSTALL_BROWSER}" = "true" ]; then \
      /opt/venv/bin/python -m playwright install-deps chromium && \
      chown -R scanner:scanner /opt/ms-playwright; \
    fi

# ------------------------------------------------------------
# Final container configuration
# ------------------------------------------------------------

WORKDIR /app

RUN mkdir -p /home/scanner && ln -sfn /app/config/nuclei-templates /home/scanner/nuclei-templates && chown -h scanner:scanner /home/scanner/nuclei-templates
USER scanner

VOLUME ["/app/output", "/app/secrets"]


ENTRYPOINT ["quiver"]

CMD ["--help"]
