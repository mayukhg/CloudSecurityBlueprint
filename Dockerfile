# SecureAI Platform - Production Dockerfile
# Multi-stage build for optimized production container

# =============================================================================
# Stage 1: Build the application
# =============================================================================
FROM node:18-alpine AS builder

# Set working directory
WORKDIR /app

# Install dependencies for building
COPY package*.json ./
RUN npm ci --only=production

# Copy source code
COPY . .

# Build the application
RUN npm run build

# =============================================================================
# Stage 2: Production runtime
# =============================================================================
FROM node:18-alpine AS production

# Install security updates and required packages
RUN apk update && apk upgrade && \
    apk add --no-cache curl && \
    rm -rf /var/cache/apk/*

# Create non-root user for security
RUN addgroup -g 1001 -S nodejs && \
    adduser -S secureai -u 1001

# Set working directory
WORKDIR /app

# Copy package files
COPY package*.json ./

# Install production dependencies only
RUN npm ci --only=production && npm cache clean --force

# Copy built application from builder stage
COPY --from=builder --chown=secureai:nodejs /app/dist ./dist
COPY --from=builder --chown=secureai:nodejs /app/server ./server
COPY --from=builder --chown=secureai:nodejs /app/shared ./shared

# Copy additional required files
COPY --chown=secureai:nodejs drizzle.config.ts ./
COPY --chown=secureai:nodejs tsconfig.json ./

# Create health check endpoint script
RUN echo '#!/bin/sh\ncurl -f http://localhost:$PORT/health || exit 1' > /health-check.sh && \
    chmod +x /health-check.sh && \
    chown secureai:nodejs /health-check.sh

# Switch to non-root user
USER secureai

# Expose application port
EXPOSE 3000

# Add health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD /health-check.sh

# Set environment variables
ENV NODE_ENV=production
ENV PORT=3000

# Start the application
CMD ["npm", "start"]