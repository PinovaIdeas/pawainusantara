# Pawai Nusantara — Mirror Server (Railway / VPS / Render)
# Node.js + Chromium (Puppeteer) untuk auto-solve Vercel Security Checkpoint.

FROM node:20-bookworm-slim

# Chromium + library yang dibutuhkan headless Chrome.
RUN apt-get update && apt-get install -y --no-install-recommends \
      chromium \
      ca-certificates \
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
    PORT=8080

WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm install --omit=dev

COPY server.js ./

EXPOSE 8080

CMD ["node", "server.js"]
