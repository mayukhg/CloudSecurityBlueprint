import { pgTable, text, serial, integer, timestamp, jsonb } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";

export const users = pgTable("users", {
  id: serial("id").primaryKey(),
  username: text("username").notNull().unique(),
  password: text("password").notNull(),
});

export const accounts = pgTable("accounts", {
  id: serial("id").primaryKey(),
  accountId: text("account_id").notNull().unique(),
  name: text("name").notNull(),
  environment: text("environment").notNull(), // production, development, staging
  securityScore: integer("security_score").notNull().default(0),
  criticalFindings: integer("critical_findings").notNull().default(0),
  highFindings: integer("high_findings").notNull().default(0),
  mediumFindings: integer("medium_findings").notNull().default(0),
  complianceScore: integer("compliance_score").notNull().default(0),
  lastScanned: timestamp("last_scanned").defaultNow(),
});

export const securityFindings = pgTable("security_findings", {
  id: serial("id").primaryKey(),
  accountId: text("account_id").notNull(),
  title: text("title").notNull(),
  description: text("description").notNull(),
  severity: text("severity").notNull(), // critical, high, medium, low
  status: text("status").notNull(), // open, in_progress, resolved
  service: text("service").notNull(), // s3, ec2, iam, etc.
  resourceId: text("resource_id"),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
});

export const chatMessages = pgTable("chat_messages", {
  id: serial("id").primaryKey(),
  sessionId: text("session_id").notNull(),
  message: text("message").notNull(),
  isUser: integer("is_user").notNull(), // 0 for AI, 1 for user
  timestamp: timestamp("timestamp").defaultNow(),
});

export const playbooks = pgTable("playbooks", {
  id: serial("id").primaryKey(),
  title: text("title").notNull(),
  description: text("description").notNull(),
  type: text("type").notNull(),
  steps: jsonb("steps").notNull(),
  estimatedTime: integer("estimated_time"), // in minutes
  difficulty: text("difficulty").notNull(), // easy, medium, hard
  status: text("status").notNull().default("ready"), // ready, draft
  createdAt: timestamp("created_at").defaultNow(),
});

export const insertUserSchema = createInsertSchema(users).pick({
  username: true,
  password: true,
});

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

export const insertSecurityFindingSchema = createInsertSchema(securityFindings).pick({
  accountId: true,
  title: true,
  description: true,
  severity: true,
  status: true,
  service: true,
  resourceId: true,
});

export const insertChatMessageSchema = createInsertSchema(chatMessages).pick({
  sessionId: true,
  message: true,
  isUser: true,
});

export const insertPlaybookSchema = createInsertSchema(playbooks).pick({
  title: true,
  description: true,
  type: true,
  steps: true,
  estimatedTime: true,
  difficulty: true,
  status: true,
});

export type InsertUser = z.infer<typeof insertUserSchema>;
export type User = typeof users.$inferSelect;

export type InsertAccount = z.infer<typeof insertAccountSchema>;
export type Account = typeof accounts.$inferSelect;

export type InsertSecurityFinding = z.infer<typeof insertSecurityFindingSchema>;
export type SecurityFinding = typeof securityFindings.$inferSelect;

export type InsertChatMessage = z.infer<typeof insertChatMessageSchema>;
export type ChatMessage = typeof chatMessages.$inferSelect;

export type InsertPlaybook = z.infer<typeof insertPlaybookSchema>;
export type Playbook = typeof playbooks.$inferSelect;
