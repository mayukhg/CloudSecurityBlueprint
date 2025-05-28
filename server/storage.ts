import { 
  users, accounts, securityFindings, chatMessages, playbooks,
  type User, type InsertUser,
  type Account, type InsertAccount,
  type SecurityFinding, type InsertSecurityFinding,
  type ChatMessage, type InsertChatMessage,
  type Playbook, type InsertPlaybook
} from "@shared/schema";

export interface IStorage {
  getUser(id: number): Promise<User | undefined>;
  getUserByUsername(username: string): Promise<User | undefined>;
  createUser(user: InsertUser): Promise<User>;
  
  getAllAccounts(): Promise<Account[]>;
  getAccount(id: number): Promise<Account | undefined>;
  getAccountByAccountId(accountId: string): Promise<Account | undefined>;
  createAccount(account: InsertAccount): Promise<Account>;
  updateAccount(id: number, updates: Partial<Account>): Promise<Account | undefined>;
  
  getSecurityFindingsByAccount(accountId: string): Promise<SecurityFinding[]>;
  getAllSecurityFindings(): Promise<SecurityFinding[]>;
  createSecurityFinding(finding: InsertSecurityFinding): Promise<SecurityFinding>;
  updateSecurityFinding(id: number, updates: Partial<SecurityFinding>): Promise<SecurityFinding | undefined>;
  
  getChatMessages(sessionId: string): Promise<ChatMessage[]>;
  createChatMessage(message: InsertChatMessage): Promise<ChatMessage>;
  
  getAllPlaybooks(): Promise<Playbook[]>;
  getPlaybook(id: number): Promise<Playbook | undefined>;
  createPlaybook(playbook: InsertPlaybook): Promise<Playbook>;
}

export class MemStorage implements IStorage {
  private users: Map<number, User>;
  private accounts: Map<number, Account>;
  private securityFindings: Map<number, SecurityFinding>;
  private chatMessages: Map<number, ChatMessage>;
  private playbooks: Map<number, Playbook>;
  private currentUserId: number;
  private currentAccountId: number;
  private currentFindingId: number;
  private currentChatId: number;
  private currentPlaybookId: number;

  constructor() {
    this.users = new Map();
    this.accounts = new Map();
    this.securityFindings = new Map();
    this.chatMessages = new Map();
    this.playbooks = new Map();
    this.currentUserId = 1;
    this.currentAccountId = 1;
    this.currentFindingId = 1;
    this.currentChatId = 1;
    this.currentPlaybookId = 1;
    
    this.initializeMockData();
  }

  private initializeMockData() {
    // Initialize mock accounts
    const mockAccounts: InsertAccount[] = [
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

    mockAccounts.forEach(account => this.createAccount(account));

    // Initialize mock security findings
    const mockFindings: InsertSecurityFinding[] = [
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

    mockFindings.forEach(finding => this.createSecurityFinding(finding));

    // Initialize mock playbooks
    const mockPlaybooks: InsertPlaybook[] = [
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

    mockPlaybooks.forEach(playbook => this.createPlaybook(playbook));
  }

  async getUser(id: number): Promise<User | undefined> {
    return this.users.get(id);
  }

  async getUserByUsername(username: string): Promise<User | undefined> {
    return Array.from(this.users.values()).find(
      (user) => user.username === username,
    );
  }

  async createUser(insertUser: InsertUser): Promise<User> {
    const id = this.currentUserId++;
    const user: User = { ...insertUser, id };
    this.users.set(id, user);
    return user;
  }

  async getAllAccounts(): Promise<Account[]> {
    return Array.from(this.accounts.values());
  }

  async getAccount(id: number): Promise<Account | undefined> {
    return this.accounts.get(id);
  }

  async getAccountByAccountId(accountId: string): Promise<Account | undefined> {
    return Array.from(this.accounts.values()).find(
      (account) => account.accountId === accountId,
    );
  }

  async createAccount(insertAccount: InsertAccount): Promise<Account> {
    const id = this.currentAccountId++;
    const account: Account = { 
      ...insertAccount, 
      id,
      lastScanned: new Date(),
    };
    this.accounts.set(id, account);
    return account;
  }

  async updateAccount(id: number, updates: Partial<Account>): Promise<Account | undefined> {
    const account = this.accounts.get(id);
    if (!account) return undefined;
    
    const updatedAccount = { ...account, ...updates };
    this.accounts.set(id, updatedAccount);
    return updatedAccount;
  }

  async getSecurityFindingsByAccount(accountId: string): Promise<SecurityFinding[]> {
    return Array.from(this.securityFindings.values()).filter(
      (finding) => finding.accountId === accountId,
    );
  }

  async getAllSecurityFindings(): Promise<SecurityFinding[]> {
    return Array.from(this.securityFindings.values());
  }

  async createSecurityFinding(insertFinding: InsertSecurityFinding): Promise<SecurityFinding> {
    const id = this.currentFindingId++;
    const finding: SecurityFinding = { 
      ...insertFinding, 
      id,
      createdAt: new Date(),
      updatedAt: new Date(),
    };
    this.securityFindings.set(id, finding);
    return finding;
  }

  async updateSecurityFinding(id: number, updates: Partial<SecurityFinding>): Promise<SecurityFinding | undefined> {
    const finding = this.securityFindings.get(id);
    if (!finding) return undefined;
    
    const updatedFinding = { ...finding, ...updates, updatedAt: new Date() };
    this.securityFindings.set(id, updatedFinding);
    return updatedFinding;
  }

  async getChatMessages(sessionId: string): Promise<ChatMessage[]> {
    return Array.from(this.chatMessages.values())
      .filter((message) => message.sessionId === sessionId)
      .sort((a, b) => a.timestamp!.getTime() - b.timestamp!.getTime());
  }

  async createChatMessage(insertMessage: InsertChatMessage): Promise<ChatMessage> {
    const id = this.currentChatId++;
    const message: ChatMessage = { 
      ...insertMessage, 
      id,
      timestamp: new Date(),
    };
    this.chatMessages.set(id, message);
    return message;
  }

  async getAllPlaybooks(): Promise<Playbook[]> {
    return Array.from(this.playbooks.values());
  }

  async getPlaybook(id: number): Promise<Playbook | undefined> {
    return this.playbooks.get(id);
  }

  async createPlaybook(insertPlaybook: InsertPlaybook): Promise<Playbook> {
    const id = this.currentPlaybookId++;
    const playbook: Playbook = { 
      ...insertPlaybook, 
      id,
      createdAt: new Date(),
    };
    this.playbooks.set(id, playbook);
    return playbook;
  }
}

export const storage = new MemStorage();
