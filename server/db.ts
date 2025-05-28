/**
 * Database Connection Configuration
 * 
 * Sets up the PostgreSQL connection using Neon's serverless driver with Drizzle ORM.
 * This configuration supports both local development and production environments.
 * 
 * Features:
 * - Serverless-compatible connection pooling
 * - WebSocket support for real-time capabilities
 * - Type-safe database operations through Drizzle ORM
 * - Automatic schema inference from shared types
 */

import { Pool, neonConfig } from '@neondatabase/serverless';
import { drizzle } from 'drizzle-orm/neon-serverless';
import ws from "ws";
import * as schema from "@shared/schema";

// Configure Neon to use WebSocket for serverless environments
neonConfig.webSocketConstructor = ws;

// Validate required environment variables
if (!process.env.DATABASE_URL) {
  throw new Error(
    "DATABASE_URL must be set. Did you forget to provision a database?",
  );
}

// Create connection pool for efficient database connections
export const pool = new Pool({ connectionString: process.env.DATABASE_URL });

// Initialize Drizzle ORM with schema for type-safe operations
export const db = drizzle({ client: pool, schema });