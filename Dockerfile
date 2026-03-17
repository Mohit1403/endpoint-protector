# Use official Node.js image which handles native modules well
FROM node:18-bullseye-slim

# Reduce interactive prompts and set production mode
ENV DEBIAN_FRONTEND=noninteractive
ENV NODE_ENV=production
ENV PORT=3000

# Install system dependencies (nmap + networking tools)
# --no-install-recommends keeps image smaller
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      curl \
      nmap \
      nmap-common \
      python3 \
      python3-pip \
      git \
      wget \
      unzip \
      build-essential \
      python3-dev \
      netcat \
      dnsutils \
      iputils-ping \
      net-tools \
      traceroute \
      whois \
      hping3 \
      tcpdump \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /usr/src/app

# Copy dependency manifests first for layer caching
COPY package*.json ./

# Install Node dependencies (production). Change to `npm ci` if you use package-lock.json.
RUN npm install --production

# Copy application source
COPY . .

# Create necessary runtime directories and set ownership
RUN mkdir -p /usr/src/app/reports \
    /usr/src/app/logs \
    /usr/src/app/uploads \
    /usr/src/app/temp \
  && chown -R node:node /usr/src/app \
  # ensure nmap is executable (should already be); no-op if already correct
  && chmod +x /usr/bin/nmap || true

# Switch to non-root "node" user (provided by official node image)
USER node

# Expose port (app should use process.env.PORT)
EXPOSE 3000

# Healthcheck: use the PORT env var if present (shell required for expansion)
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD sh -c 'curl -f http://localhost:${PORT:-3000}/health || exit 1'

# Start the application. Keep as `node index.js` if that's your entrypoint.
CMD ["node", "index.js"]
