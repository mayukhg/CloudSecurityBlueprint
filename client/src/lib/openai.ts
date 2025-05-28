/**
 * OpenAI Integration Types and Utilities
 * 
 * This file defines TypeScript interfaces and utility constants for working with
 * AI-powered features throughout the SecureAI platform. These types ensure
 * consistency between the frontend and backend when handling AI responses.
 * 
 * Note: Actual API calls to OpenAI are made from the server for security reasons.
 * This file only contains type definitions and UI helper utilities.
 */

// Type definition for policy explanation responses from AI
export interface PolicyExplanation {
  explanation: string; // HTML-formatted explanation of the security policy
}

// Structure for individual steps in remediation guidance
export interface RemediationStep {
  stepNumber: number;
  title: string;
  description: string;
  commands?: string[]; // AWS CLI commands for this step
  consoleSteps?: string[]; // Manual AWS Console steps
}

// Complete remediation guide structure returned by AI
export interface RemediationGuide {
  title: string;
  description: string;
  difficulty: "easy" | "medium" | "hard";
  estimatedTime: string; // Human-readable time estimate
  steps: RemediationStep[];
  additionalResources?: Array<{
    title: string;
    url: string;
    type: "documentation" | "video" | "checklist";
  }>;
}

// Chat message structure for security concierge conversations
export interface ChatMessage {
  id: number;
  sessionId: string; // Groups messages into conversations
  message: string;
  isUser: number; // 0 for AI responses, 1 for user messages
  timestamp: Date;
}

// AI-generated security report structure
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
  aiSummary: string; // AI-generated business-friendly summary
  generatedAt: Date;
}

// UI color schemes for different difficulty levels
export const difficultyColors = {
  easy: "bg-green-100 text-green-800",
  medium: "bg-yellow-100 text-yellow-800",
  hard: "bg-red-100 text-red-800",
};

// UI color schemes for security finding severity levels
export const severityColors = {
  critical: "bg-red-100 text-red-800",
  high: "bg-orange-100 text-orange-800",
  medium: "bg-yellow-100 text-yellow-800",
  low: "bg-gray-100 text-gray-800",
};

// UI color schemes for finding status indicators
export const statusColors = {
  open: "bg-gray-100 text-gray-800",
  in_progress: "bg-yellow-100 text-yellow-800",
  resolved: "bg-green-100 text-green-800",
};
