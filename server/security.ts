/**
 * SecureAI Platform - Security Middleware and Utilities
 * 
 * This module provides comprehensive security controls including:
 * - Authentication and authorization middleware
 * - Input validation and sanitization
 * - Rate limiting and DDoS protection
 * - Security headers and CORS configuration
 * - Audit logging and monitoring
 * - Error handling without information disclosure
 */

import { Request, Response, NextFunction } from 'express';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import cors from 'cors';

/**
 * Security Configuration Constants
 */
export const SECURITY_CONFIG = {
  // Rate limiting thresholds
  GENERAL_RATE_LIMIT: {
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // 100 requests per window
    message: "Too many requests from this IP, please try again later"
  },
  
  AI_RATE_LIMIT: {
    windowMs: 60 * 1000, // 1 minute
    max: 10, // 10 AI requests per minute
    message: "AI request limit exceeded, please wait before making more AI-powered requests"
  },
  
  CHAT_RATE_LIMIT: {
    windowMs: 60 * 1000, // 1 minute
    max: 20, // 20 chat messages per minute
    message: "Chat rate limit exceeded, please slow down your conversation"
  },
  
  // Input validation limits
  MAX_POLICY_LENGTH: 50000,
  MAX_CHAT_MESSAGE_LENGTH: 2000,
  MAX_DESCRIPTION_LENGTH: 5000,
  
  // Security headers
  ALLOWED_ORIGINS: process.env.NODE_ENV === 'production' 
    ? process.env.ALLOWED_ORIGINS?.split(',') || ['https://your-domain.com']
    : ['http://localhost:3000', 'http://localhost:5173']
};

/**
 * Rate Limiting Factory Function
 * Creates rate limiters with standardized configuration
 */
export const createRateLimiter = (windowMs: number, max: number, message: string) => {
  return rateLimit({
    windowMs,
    max,
    message: { error: message },
    standardHeaders: true,
    legacyHeaders: false,
    // Skip rate limiting for health checks
    skip: (req: Request) => req.path === '/health'
  });
};

/**
 * Security Rate Limiters
 */
export const generalRateLimit = createRateLimiter(
  SECURITY_CONFIG.GENERAL_RATE_LIMIT.windowMs,
  SECURITY_CONFIG.GENERAL_RATE_LIMIT.max,
  SECURITY_CONFIG.GENERAL_RATE_LIMIT.message
);

export const aiRateLimit = createRateLimiter(
  SECURITY_CONFIG.AI_RATE_LIMIT.windowMs,
  SECURITY_CONFIG.AI_RATE_LIMIT.max,
  SECURITY_CONFIG.AI_RATE_LIMIT.message
);

export const chatRateLimit = createRateLimiter(
  SECURITY_CONFIG.CHAT_RATE_LIMIT.windowMs,
  SECURITY_CONFIG.CHAT_RATE_LIMIT.max,
  SECURITY_CONFIG.CHAT_RATE_LIMIT.message
);

/**
 * Helmet Security Headers Configuration
 * Implements comprehensive security headers for protection against various attacks
 */
export const helmetConfig = helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'", "https://api.openai.com"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"],
    },
  },
  crossOriginEmbedderPolicy: false,
  hsts: {
    maxAge: 31536000, // 1 year
    includeSubDomains: true,
    preload: true
  }
});

/**
 * CORS Configuration
 * Secure cross-origin resource sharing setup
 */
export const corsConfig = cors({
  origin: SECURITY_CONFIG.ALLOWED_ORIGINS,
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
  exposedHeaders: ['X-RateLimit-Limit', 'X-RateLimit-Remaining'],
  maxAge: 86400 // 24 hours
});

/**
 * Input Sanitization Utilities
 */
export class InputSanitizer {
  /**
   * Remove potentially dangerous HTML/JavaScript content
   */
  static sanitizeHtml(input: string): string {
    return input
      .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '') // Remove script tags
      .replace(/javascript:/gi, '') // Remove javascript: protocols
      .replace(/on\w+\s*=/gi, '') // Remove event handlers
      .trim();
  }

  /**
   * Sanitize text input for database storage
   */
  static sanitizeText(input: string): string {
    return input
      .replace(/[\x00-\x1F\x7F]/g, '') // Remove control characters
      .trim();
  }

  /**
   * Validate session ID format
   */
  static validateSessionId(sessionId: string): boolean {
    return /^[a-zA-Z0-9-_]{1,100}$/.test(sessionId);
  }
}

/**
 * Audit Logging System
 * Comprehensive logging for security events and compliance
 */
export class AuditLogger {
  static log(action: string, userId: string | null, details: any, req: Request): void {
    const logEntry = {
      timestamp: new Date().toISOString(),
      action,
      userId: userId || 'anonymous',
      ip: req.ip || req.socket.remoteAddress,
      userAgent: req.get('User-Agent'),
      method: req.method,
      url: req.originalUrl,
      details: typeof details === 'object' ? JSON.stringify(details) : details,
      sessionId: req.session?.id || 'no-session'
    };
    
    // Log to secure audit trail
    console.log(`[AUDIT] ${JSON.stringify(logEntry)}`);
    
    // In production, also send to centralized logging service
    if (process.env.NODE_ENV === 'production') {
      // TODO: Integrate with CloudWatch, Splunk, or other logging service
    }
  }

  static logSecurityEvent(event: string, severity: 'low' | 'medium' | 'high' | 'critical', req: Request, details?: any): void {
    this.log(`SECURITY_EVENT:${event}`, null, { severity, ...details }, req);
    
    // Alert on high/critical security events
    if (severity === 'high' || severity === 'critical') {
      console.error(`[SECURITY ALERT] ${event}: ${JSON.stringify(details)}`);
      // TODO: Integrate with alerting service (SNS, PagerDuty, etc.)
    }
  }
}

/**
 * Authentication Middleware
 * Basic authentication setup - extend as needed for your auth system
 */
export const authenticationMiddleware = (req: Request, res: Response, next: NextFunction) => {
  // For now, we'll skip authentication but log all access
  AuditLogger.log('api_access', null, { endpoint: req.path }, req);
  
  // TODO: Implement proper authentication
  // - JWT token validation
  // - Session management
  // - Role-based access control
  
  next();
};

/**
 * Error Handler Middleware
 * Secure error handling without information disclosure
 */
export const securityErrorHandler = (err: any, req: Request, res: Response, next: NextFunction) => {
  // Log the full error for debugging
  AuditLogger.logSecurityEvent('error_occurred', 'medium', req, {
    error: err.message,
    stack: err.stack,
    endpoint: req.path
  });

  // Return generic error message to prevent information disclosure
  const isDevelopment = process.env.NODE_ENV === 'development';
  
  res.status(err.status || 500).json({
    error: isDevelopment ? err.message : 'An error occurred while processing your request',
    ...(isDevelopment && { stack: err.stack })
  });
};

/**
 * Request Validation Middleware
 * Validates common request properties for security
 */
export const requestValidationMiddleware = (req: Request, res: Response, next: NextFunction) => {
  // Check for excessively large requests
  const contentLength = parseInt(req.get('content-length') || '0');
  if (contentLength > 10 * 1024 * 1024) { // 10MB limit
    AuditLogger.logSecurityEvent('large_request_blocked', 'high', req, {
      contentLength,
      endpoint: req.path
    });
    return res.status(413).json({ error: 'Request too large' });
  }

  // Validate content type for POST/PUT requests
  if (['POST', 'PUT', 'PATCH'].includes(req.method)) {
    const contentType = req.get('content-type');
    if (!contentType || !contentType.includes('application/json')) {
      AuditLogger.logSecurityEvent('invalid_content_type', 'low', req, {
        contentType,
        endpoint: req.path
      });
      return res.status(400).json({ error: 'Invalid content type' });
    }
  }

  next();
};

/**
 * Security Headers Middleware
 * Additional security headers beyond Helmet
 */
export const additionalSecurityHeaders = (req: Request, res: Response, next: NextFunction) => {
  // Prevent caching of sensitive endpoints
  if (req.path.includes('/api/')) {
    res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    res.set('Pragma', 'no-cache');
    res.set('Expires', '0');
  }

  // Add custom security headers
  res.set('X-Content-Type-Options', 'nosniff');
  res.set('X-Frame-Options', 'DENY');
  res.set('X-XSS-Protection', '1; mode=block');
  res.set('Referrer-Policy', 'strict-origin-when-cross-origin');

  next();
};