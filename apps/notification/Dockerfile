FROM node:22-alpine AS builder

WORKDIR /app

# Copy package files and install dependencies
COPY package*.json ./
COPY tsconfig*.json ./
COPY nest-cli.json ./
RUN npm ci

# Copy source code
COPY apps/notification ./apps/notification
COPY libs ./libs

# Build the application
RUN npm run build notification

FROM node:22-alpine

WORKDIR /app

# Copy package files and install production dependencies
COPY package*.json ./
RUN npm ci --only=production

# Copy built app from builder stage
COPY --from=builder /app/dist/apps/notification ./dist

CMD ["node", "dist/main.js"]
