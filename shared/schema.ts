import { pgTable, text, serial, integer, timestamp, jsonb } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";

/**
 * Database Schema for SecureAI Platform
 * 
 * This file defines the complete database schema using Drizzle ORM for PostgreSQL.
 * It includes tables for users, AWS accounts, security findings, chat messages, and playbooks.
 * All schemas include corresponding Zod validation schemas for type-safe API operations.
 */

// User authentication and management table
export const users = pgTable("users", {
  id: serial("id").primaryKey(),
  username: text("username").notNull().unique(),
  password: text("password").notNull(), // TODO: Should be hashed in production
});

// AWS account information and security metrics
export const accounts = pgTable("accounts", {
  id: serial("id").primaryKey(),
  accountId: text("account_id").notNull().unique(), // AWS Account ID (12-digit)
  name: text("name").notNull(), // Human-readable account name
  environment: text("environment").notNull(), // production, development, staging
  securityScore: integer("security_score").notNull().default(0), // Overall security score (0-100)
  criticalFindings: integer("critical_findings").notNull().default(0), // Count of critical issues
  highFindings: integer("high_findings").notNull().default(0), // Count of high severity issues
  mediumFindings: integer("medium_findings").notNull().default(0), // Count of medium severity issues
  complianceScore: integer("compliance_score").notNull().default(0), // Compliance percentage (0-100)
  lastScanned: timestamp("last_scanned").defaultNow(), // Last security scan timestamp
});

// Individual security vulnerabilities and issues
export const securityFindings = pgTable("security_findings", {
  id: serial("id").primaryKey(),
  accountId: text("account_id").notNull(), // References accounts.accountId
  title: text("title").notNull(), // Brief description of the finding
  description: text("description").notNull(), // Detailed explanation
  severity: text("severity").notNull(), // critical, high, medium, low
  status: text("status").notNull(), // open, in_progress, resolved
  service: text("service").notNull(), // AWS service (s3, ec2, iam, etc.)
  resourceId: text("resource_id"), // ARN or resource identifier (optional)
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
});

// Chat conversations with the AI security concierge
export const chatMessages = pgTable("chat_messages", {
  id: serial("id").primaryKey(),
  sessionId: text("session_id").notNull(), // Groups messages by conversation
  message: text("message").notNull(), // The actual message content
  isUser: integer("is_user").notNull(), // 0 for AI responses, 1 for user messages
  timestamp: timestamp("timestamp").defaultNow(),
});

// Generated security playbooks and procedures
export const playbooks = pgTable("playbooks", {
  id: serial("id").primaryKey(),
  title: text("title").notNull(),
  description: text("description").notNull(),
  type: text("type").notNull(), // new-account, incident-response, compliance-audit, etc.
  steps: jsonb("steps").notNull(), // JSON array of procedural steps
  estimatedTime: integer("estimated_time"), // Completion time in minutes
  difficulty: text("difficulty").notNull(), // easy, medium, hard
  status: text("status").notNull().default("ready"), // ready, draft
  createdAt: timestamp("created_at").defaultNow(),
});

// Zod validation schemas for API request validation
// These schemas ensure type safety when creating new records

// User creation schema - excludes auto-generated ID
export const insertUserSchema = createInsertSchema(users).pick({
  username: true,
  password: true,
});

// Account creation schema - excludes ID and lastScanned (auto-generated)
export const insertAccountSchema = createInsertSchema(accounts).pick({
  accountId: true,
  name: true,
  environment: true,
  securityScore: true,
  criticalFindings: true,
  highFindings: true,
  mediumFindings: true,
  complianceScore: true,
});

// Security finding creation schema - excludes ID and timestamps (auto-generated)
export const insertSecurityFindingSchema = createInsertSchema(securityFindings).pick({
  accountId: true,
  title: true,
  description: true,
  severity: true,
  status: true,
  service: true,
  resourceId: true,
});

// Chat message creation schema - excludes ID and timestamp (auto-generated)
export const insertChatMessageSchema = createInsertSchema(chatMessages).pick({
  sessionId: true,
  message: true,
  isUser: true,
});

// Playbook creation schema - excludes ID and createdAt (auto-generated)
export const insertPlaybookSchema = createInsertSchema(playbooks).pick({
  title: true,
  description: true,
  type: true,
  steps: true,
  estimatedTime: true,
  difficulty: true,
  status: true,
});

// TypeScript types for insert operations (creating new records)
export type InsertUser = z.infer<typeof insertUserSchema>;
export type InsertAccount = z.infer<typeof insertAccountSchema>;
export type InsertSecurityFinding = z.infer<typeof insertSecurityFindingSchema>;
export type InsertChatMessage = z.infer<typeof insertChatMessageSchema>;
export type InsertPlaybook = z.infer<typeof insertPlaybookSchema>;

// TypeScript types for select operations (reading existing records)
export type User = typeof users.$inferSelect;
export type Account = typeof accounts.$inferSelect;
export type SecurityFinding = typeof securityFindings.$inferSelect;
export type ChatMessage = typeof chatMessages.$inferSelect;
export type Playbook = typeof playbooks.$inferSelect;
