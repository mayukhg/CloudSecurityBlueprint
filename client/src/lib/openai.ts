// This file contains client-side utilities for working with OpenAI responses
// The actual API calls are made from the server

export interface PolicyExplanation {
  explanation: string;
}

export interface RemediationStep {
  stepNumber: number;
  title: string;
  description: string;
  commands?: string[];
  consoleSteps?: string[];
}

export interface RemediationGuide {
  title: string;
  description: string;
  difficulty: "easy" | "medium" | "hard";
  estimatedTime: string;
  steps: RemediationStep[];
  additionalResources?: Array<{
    title: string;
    url: string;
    type: "documentation" | "video" | "checklist";
  }>;
}

export interface ChatMessage {
  id: number;
  sessionId: string;
  message: string;
  isUser: number; // 0 for AI, 1 for user
  timestamp: Date;
}

export interface SecurityReport {
  account: {
    id: number;
    accountId: string;
    name: string;
    environment: string;
    securityScore: number;
    criticalFindings: number;
    highFindings: number;
    mediumFindings: number;
    complianceScore: number;
  };
  findings: Array<{
    id: number;
    title: string;
    description: string;
    severity: string;
    status: string;
    service: string;
  }>;
  aiSummary: string;
  generatedAt: Date;
}

export const difficultyColors = {
  easy: "bg-green-100 text-green-800",
  medium: "bg-yellow-100 text-yellow-800",
  hard: "bg-red-100 text-red-800",
};

export const severityColors = {
  critical: "bg-red-100 text-red-800",
  high: "bg-orange-100 text-orange-800",
  medium: "bg-yellow-100 text-yellow-800",
  low: "bg-gray-100 text-gray-800",
};

export const statusColors = {
  open: "bg-gray-100 text-gray-800",
  in_progress: "bg-yellow-100 text-yellow-800",
  resolved: "bg-green-100 text-green-800",
};
