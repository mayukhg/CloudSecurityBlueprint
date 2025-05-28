/**
 * Data Access Layer for SecureAI Platform
 * 
 * This module provides a clean abstraction layer over database operations.
 * It implements the repository pattern to separate business logic from data persistence.
 * 
 * Features:
 * - Type-safe database operations using Drizzle ORM
 * - Consistent interface for all data operations
 * - Automatic mock data initialization for development
 * - Support for user management, security findings, chat, and playbooks
 */

import { 
  users, accounts, securityFindings, chatMessages, playbooks,
  type User, type InsertUser,
  type Account, type InsertAccount,
  type SecurityFinding, type InsertSecurityFinding,
  type ChatMessage, type InsertChatMessage,
  type Playbook, type InsertPlaybook
} from "@shared/schema";
import { db } from "./db";
import { eq } from "drizzle-orm";

/**
 * Storage interface defining all data operations
 * This abstraction allows for easy testing and potential storage backend changes
 */
export interface IStorage {
  // User management operations
  getUser(id: number): Promise<User | undefined>;
  getUserByUsername(username: string): Promise<User | undefined>;
  createUser(user: InsertUser): Promise<User>;
  
  // AWS account management operations
  getAllAccounts(): Promise<Account[]>;
  getAccount(id: number): Promise<Account | undefined>;
  getAccountByAccountId(accountId: string): Promise<Account | undefined>;
  createAccount(account: InsertAccount): Promise<Account>;
  updateAccount(id: number, updates: Partial<Account>): Promise<Account | undefined>;
  
  // Security findings operations
  getSecurityFindingsByAccount(accountId: string): Promise<SecurityFinding[]>;
  getAllSecurityFindings(): Promise<SecurityFinding[]>;
  createSecurityFinding(finding: InsertSecurityFinding): Promise<SecurityFinding>;
  updateSecurityFinding(id: number, updates: Partial<SecurityFinding>): Promise<SecurityFinding | undefined>;
  
  // Chat messaging operations
  getChatMessages(sessionId: string): Promise<ChatMessage[]>;
  createChatMessage(message: InsertChatMessage): Promise<ChatMessage>;
  
  // Security playbooks operations
  getAllPlaybooks(): Promise<Playbook[]>;
  getPlaybook(id: number): Promise<Playbook | undefined>;
  createPlaybook(playbook: InsertPlaybook): Promise<Playbook>;
}

/**
 * PostgreSQL implementation of the storage interface
 * Uses Drizzle ORM for type-safe database operations
 */
export class DatabaseStorage implements IStorage {
  constructor() {
    // Initialize with sample data for development/demo purposes
    this.initializeMockData();
  }

  /**
   * Initialize demo data for development and testing
   * This method populates the database with sample AWS accounts, security findings, and playbooks
   * Only runs if the database is empty to avoid duplicate data
   */
  private async initializeMockData() {
    try {
      // Check if data already exists to prevent duplicate initialization
      const existingAccounts = await db.select().from(accounts).limit(1);
      if (existingAccounts.length > 0) {
        return; // Data already initialized, skip
      }

      // Sample AWS accounts with realistic security metrics
      const sampleAccounts: InsertAccount[] = [
        {
          accountId: "123456789012",
          name: "Production Web Services",
          environment: "production",
          securityScore: 72,
          criticalFindings: 3,
          highFindings: 7,
          mediumFindings: 12,
          complianceScore: 78,
        },
        {
          accountId: "123456789013",
          name: "Development API Backend",
          environment: "development",
          securityScore: 91,
          criticalFindings: 0,
          highFindings: 0,
          mediumFindings: 1,
          complianceScore: 96,
        },
        {
          accountId: "123456789014",
          name: "Staging Database",
          environment: "staging",
          securityScore: 85,
          criticalFindings: 0,
          highFindings: 2,
          mediumFindings: 4,
          complianceScore: 89,
        },
      ];

      await db.insert(accounts).values(sampleAccounts);

      // Sample security findings demonstrating common AWS issues
      const sampleFindings: InsertSecurityFinding[] = [
        {
          accountId: "123456789012",
          title: "Public S3 bucket with sensitive data",
          description: "S3 bucket allows public read access and contains sensitive customer data",
          severity: "critical",
          status: "in_progress",
          service: "s3",
          resourceId: "arn:aws:s3:::prod-customer-data",
        },
        {
          accountId: "123456789012",
          title: "Overprivileged IAM role",
          description: "IAM role has excessive permissions including admin access",
          severity: "high",
          status: "open",
          service: "iam",
          resourceId: "arn:aws:iam::123456789012:role/ProductionRole",
        },
        {
          accountId: "123456789014",
          title: "Unencrypted RDS instance",
          description: "RDS database instance is not encrypted at rest",
          severity: "high",
          status: "resolved",
          service: "rds",
          resourceId: "arn:aws:rds:us-east-1:123456789014:db:staging-db",
        },
      ];

      await db.insert(securityFindings).values(sampleFindings);

      // Sample security playbooks for common scenarios
      const samplePlaybooks: InsertPlaybook[] = [
        {
          title: "New AWS Account Setup",
          description: "Complete checklist for setting up baseline security controls on new AWS accounts including SCPs, GuardDuty, and Config rules.",
          type: "new-account",
          steps: [
            { title: "Enable CloudTrail", description: "Set up CloudTrail for audit logging", commands: ["aws cloudtrail create-trail --name audit-trail"] },
            { title: "Configure GuardDuty", description: "Enable GuardDuty threat detection", commands: ["aws guardduty create-detector"] },
            { title: "Setup Config Rules", description: "Deploy baseline Config rules", commands: ["aws configservice put-config-rule"] },
          ],
          estimatedTime: 45,
          difficulty: "medium",
          status: "ready",
        },
        {
          title: "Security Incident Response",
          description: "Immediate response procedures for security incidents including containment, investigation, and recovery steps.",
          type: "incident-response",
          steps: [
            { title: "Assess Impact", description: "Determine scope and severity of incident", commands: [] },
            { title: "Contain Threat", description: "Isolate affected resources", commands: ["aws ec2 stop-instances"] },
            { title: "Investigate", description: "Gather evidence and analyze logs", commands: ["aws logs filter-log-events"] },
          ],
          estimatedTime: 30,
          difficulty: "hard",
          status: "ready",
        },
      ];

      await db.insert(playbooks).values(samplePlaybooks);
    } catch (error) {
      console.log("Sample data initialization skipped:", error);
    }
  }

  // === USER MANAGEMENT OPERATIONS ===
  
  /** Retrieve a user by their unique ID */
  async getUser(id: number): Promise<User | undefined> {
    const [user] = await db.select().from(users).where(eq(users.id, id));
    return user || undefined;
  }

  /** Find a user by their username for authentication */
  async getUserByUsername(username: string): Promise<User | undefined> {
    const [user] = await db.select().from(users).where(eq(users.username, username));
    return user || undefined;
  }

  /** Create a new user account */
  async createUser(insertUser: InsertUser): Promise<User> {
    const [user] = await db
      .insert(users)
      .values(insertUser)
      .returning();
    return user;
  }

  // === AWS ACCOUNT MANAGEMENT OPERATIONS ===

  /** Get all AWS accounts in the system */
  async getAllAccounts(): Promise<Account[]> {
    return await db.select().from(accounts);
  }

  /** Retrieve a specific account by internal ID */
  async getAccount(id: number): Promise<Account | undefined> {
    const [account] = await db.select().from(accounts).where(eq(accounts.id, id));
    return account || undefined;
  }

  /** Find an account by AWS Account ID (12-digit identifier) */
  async getAccountByAccountId(accountId: string): Promise<Account | undefined> {
    const [account] = await db.select().from(accounts).where(eq(accounts.accountId, accountId));
    return account || undefined;
  }

  /** Add a new AWS account to monitoring */
  async createAccount(insertAccount: InsertAccount): Promise<Account> {
    const [account] = await db
      .insert(accounts)
      .values(insertAccount)
      .returning();
    return account;
  }

  /** Update account information and security metrics */
  async updateAccount(id: number, updates: Partial<Account>): Promise<Account | undefined> {
    const [account] = await db
      .update(accounts)
      .set(updates)
      .where(eq(accounts.id, id))
      .returning();
    return account || undefined;
  }

  // === SECURITY FINDINGS OPERATIONS ===

  /** Get all security findings for a specific AWS account */
  async getSecurityFindingsByAccount(accountId: string): Promise<SecurityFinding[]> {
    return await db.select().from(securityFindings).where(eq(securityFindings.accountId, accountId));
  }

  /** Retrieve all security findings across all accounts */
  async getAllSecurityFindings(): Promise<SecurityFinding[]> {
    return await db.select().from(securityFindings);
  }

  /** Create a new security finding/vulnerability record */
  async createSecurityFinding(insertFinding: InsertSecurityFinding): Promise<SecurityFinding> {
    const [finding] = await db
      .insert(securityFindings)
      .values(insertFinding)
      .returning();
    return finding;
  }

  /** Update the status or details of a security finding */
  async updateSecurityFinding(id: number, updates: Partial<SecurityFinding>): Promise<SecurityFinding | undefined> {
    const [finding] = await db
      .update(securityFindings)
      .set(updates)
      .where(eq(securityFindings.id, id))
      .returning();
    return finding || undefined;
  }

  // === CHAT MESSAGING OPERATIONS ===

  /** Get all messages for a specific chat session */
  async getChatMessages(sessionId: string): Promise<ChatMessage[]> {
    return await db.select().from(chatMessages).where(eq(chatMessages.sessionId, sessionId));
  }

  /** Store a new chat message (user or AI response) */
  async createChatMessage(insertMessage: InsertChatMessage): Promise<ChatMessage> {
    const [message] = await db
      .insert(chatMessages)
      .values(insertMessage)
      .returning();
    return message;
  }

  // === SECURITY PLAYBOOKS OPERATIONS ===

  /** Get all available security playbooks */
  async getAllPlaybooks(): Promise<Playbook[]> {
    return await db.select().from(playbooks);
  }

  /** Retrieve a specific playbook by ID */
  async getPlaybook(id: number): Promise<Playbook | undefined> {
    const [playbook] = await db.select().from(playbooks).where(eq(playbooks.id, id));
    return playbook || undefined;
  }

  /** Save a newly generated security playbook */
  async createPlaybook(insertPlaybook: InsertPlaybook): Promise<Playbook> {
    const [playbook] = await db
      .insert(playbooks)
      .values(insertPlaybook)
      .returning();
    return playbook;
  }
}

export const storage = new DatabaseStorage();
