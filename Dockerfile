# Pawai Nusantara — Mirror Server (Railway / VPS / Render)
# Node.js + Chromium (Puppeteer) untuk lolos Vercel Security Checkpoint,
# plus Python + nodriver (EzSolver) untuk solve Cloudflare Turnstile.

FROM node:20-bookworm-slim

# Chromium + Python + Xvfb + library yang dibutuhkan headless Chrome.
RUN apt-get update && apt-get install -y --no-install-recommends \
      chromium \
      ca-certificates \
      openssl \
      python3 \
      python3-pip \
      xvfb \
      fonts-liberation \
      fonts-noto-color-emoji \
      libnss3 \
      libnspr4 \
      libatk1.0-0 \
      libatk-bridge2.0-0 \
      libcups2 \
      libdrm2 \
      libxkbcommon0 \
      libxcomposite1 \
      libxdamage1 \
      libxfixes3 \
      libxrandr2 \
      libgbm1 \
      libpango-1.0-0 \
      libcairo2 \
      libasound2 \
      libatspi2.0-0 \
    && rm -rf /var/lib/apt/lists/*

ENV NODE_ENV=production \
    PUPPETEER_SKIP_DOWNLOAD=true \
    CHROMIUM_PATH=/usr/bin/chromium \
    CHROME_PATH=/usr/bin/chromium \
    ORIGIN_HOST=pawainusantara.vercel.app \
    DISPLAY=:99 \
    MAX_WORKERS=1 \
    PORT=8080

WORKDIR /app

# Python deps untuk EzSolver (Turnstile solver).
COPY ezsolver/requirements.txt ./ezsolver/requirements.txt
RUN pip3 install --no-cache-dir --break-system-packages -r ezsolver/requirements.txt

COPY package.json package-lock.json* ./
RUN npm install --omit=dev

COPY server.js ./
COPY ezsolver ./ezsolver
COPY start.sh ./
RUN chmod +x start.sh

EXPOSE 8080

CMD ["bash", "start.sh"]
