import type { Express } from "express";
import { createServer, type Server } from "http";
import { storage } from "./storage";
import { z } from "zod";
import { insertChatMessageSchema } from "@shared/schema";
import OpenAI from "openai";

const openai = new OpenAI({ 
  apiKey: process.env.OPENAI_API_KEY || process.env.OPENAI_API_KEY_ENV_VAR || "your-openai-api-key"
});

export async function registerRoutes(app: Express): Promise<Server> {
  
  // Dashboard endpoint - get overview statistics
  app.get("/api/dashboard/overview", async (req, res) => {
    try {
      const accounts = await storage.getAllAccounts();
      const findings = await storage.getAllSecurityFindings();
      
      const totalAccounts = accounts.length;
      const criticalFindings = findings.filter(f => f.severity === "critical").length;
      const avgComplianceScore = Math.round(
        accounts.reduce((sum, acc) => sum + acc.complianceScore, 0) / accounts.length
      );
      const aiResolutions = 1248; // Mock data for AI resolutions this month
      
      res.json({
        totalAccounts,
        criticalFindings,
        complianceScore: avgComplianceScore,
        aiResolutions,
      });
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch dashboard overview" });
    }
  });

  // Get all accounts
  app.get("/api/accounts", async (req, res) => {
    try {
      const accounts = await storage.getAllAccounts();
      res.json(accounts);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch accounts" });
    }
  });

  // Get security findings for all accounts or specific account
  app.get("/api/security-findings", async (req, res) => {
    try {
      const { accountId } = req.query;
      let findings;
      
      if (accountId) {
        findings = await storage.getSecurityFindingsByAccount(accountId as string);
      } else {
        findings = await storage.getAllSecurityFindings();
      }
      
      res.json(findings);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch security findings" });
    }
  });

  // Policy Copilot - explain security policy
  app.post("/api/policy-copilot/explain", async (req, res) => {
    try {
      const { policy } = req.body;
      
      if (!policy || typeof policy !== "string") {
        return res.status(400).json({ error: "Policy text is required" });
      }

      const prompt = `You are a security expert. Explain the following security policy in plain English that a non-security person can understand. Break down what it does, its impact, and provide recommendations if applicable. Format your response as HTML with proper paragraphs, lists, and emphasis.

Policy to explain:
${policy}

Provide a clear, structured explanation with:
1. What this policy does (summary)
2. Specific rules and restrictions
3. Impact on users/resources
4. Recommendations for improvement (if any)`;

      // the newest OpenAI model is "gpt-4o" which was released May 13, 2024. do not change this unless explicitly requested by the user
      const response = await openai.chat.completions.create({
        model: "gpt-4o",
        messages: [
          {
            role: "system",
            content: "You are a helpful security expert who explains complex policies in simple terms."
          },
          {
            role: "user",
            content: prompt
          }
        ],
        max_tokens: 1500,
      });

      const explanation = response.choices[0].message.content;
      res.json({ explanation });
    } catch (error: any) {
      console.error("Policy explanation error:", error);
      res.status(500).json({ error: "Failed to explain policy. Please check your OpenAI API key." });
    }
  });

  // Remediation Assistant - get remediation steps
  app.post("/api/remediation/steps", async (req, res) => {
    try {
      const { issueType, description } = req.body;
      
      if (!issueType) {
        return res.status(400).json({ error: "Issue type is required" });
      }

      const prompt = `Generate detailed remediation steps for fixing this AWS security issue: ${issueType}. 
      ${description ? `Additional context: ${description}` : ''}
      
      Provide a JSON response with the following structure:
      {
        "title": "Fix [Issue Title]",
        "description": "Brief description of what will be fixed",
        "difficulty": "easy|medium|hard",
        "estimatedTime": "time in minutes",
        "steps": [
          {
            "stepNumber": 1,
            "title": "Step title",
            "description": "Detailed explanation",
            "commands": ["aws cli command if applicable"],
            "consoleSteps": ["Manual steps in AWS console if applicable"]
          }
        ],
        "additionalResources": [
          {
            "title": "Resource title",
            "url": "https://example.com",
            "type": "documentation|video|checklist"
          }
        ]
      }`;

      // the newest OpenAI model is "gpt-4o" which was released May 13, 2024. do not change this unless explicitly requested by the user
      const response = await openai.chat.completions.create({
        model: "gpt-4o",
        messages: [
          {
            role: "system",
            content: "You are an AWS security expert. Generate practical, step-by-step remediation guidance in JSON format."
          },
          {
            role: "user",
            content: prompt
          }
        ],
        response_format: { type: "json_object" },
      });

      const remediation = JSON.parse(response.choices[0].message.content || "{}");
      res.json(remediation);
    } catch (error: any) {
      console.error("Remediation error:", error);
      res.status(500).json({ error: "Failed to generate remediation steps. Please check your OpenAI API key." });
    }
  });

  // Chat endpoint
  app.get("/api/chat/messages/:sessionId", async (req, res) => {
    try {
      const { sessionId } = req.params;
      const messages = await storage.getChatMessages(sessionId);
      res.json(messages);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch chat messages" });
    }
  });

  app.post("/api/chat/message", async (req, res) => {
    try {
      const validatedData = insertChatMessageSchema.parse(req.body);
      
      // Store user message
      const userMessage = await storage.createChatMessage(validatedData);
      
      // Generate AI response
      const prompt = `You are a helpful AWS security assistant. The user is asking about their AWS security. 
      Provide practical, specific advice. If they ask about account status, refer to common security issues.
      Keep responses concise and actionable.
      
      User question: ${validatedData.message}`;

      // the newest OpenAI model is "gpt-4o" which was released May 13, 2024. do not change this unless explicitly requested by the user
      const response = await openai.chat.completions.create({
        model: "gpt-4o",
        messages: [
          {
            role: "system",
            content: "You are a helpful AWS security expert assistant. Provide practical, actionable advice."
          },
          {
            role: "user",
            content: prompt
          }
        ],
        max_tokens: 500,
      });

      const aiResponse = response.choices[0].message.content;
      
      // Store AI response
      const aiMessage = await storage.createChatMessage({
        sessionId: validatedData.sessionId,
        message: aiResponse || "I'm sorry, I couldn't process your request.",
        isUser: 0,
      });

      res.json({ userMessage, aiMessage });
    } catch (error: any) {
      console.error("Chat error:", error);
      if (error.name === 'ZodError') {
        return res.status(400).json({ error: "Invalid message format" });
      }
      res.status(500).json({ error: "Failed to process chat message. Please check your OpenAI API key." });
    }
  });

  // Playbooks endpoints
  app.get("/api/playbooks", async (req, res) => {
    try {
      const playbooks = await storage.getAllPlaybooks();
      res.json(playbooks);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch playbooks" });
    }
  });

  app.post("/api/playbooks/generate", async (req, res) => {
    try {
      const { type, requirements } = req.body;
      
      if (!type) {
        return res.status(400).json({ error: "Playbook type is required" });
      }

      const prompt = `Generate a detailed security playbook for: ${type}
      ${requirements ? `Additional requirements: ${requirements}` : ''}
      
      Create a comprehensive playbook in JSON format:
      {
        "title": "Playbook title",
        "description": "What this playbook accomplishes",
        "type": "${type}",
        "difficulty": "easy|medium|hard",
        "estimatedTime": "time in minutes as number",
        "steps": [
          {
            "title": "Step title",
            "description": "What to do in this step",
            "commands": ["aws cli commands if applicable"],
            "consoleSteps": ["manual steps if needed"],
            "verification": "How to verify this step is complete"
          }
        ],
        "prerequisites": ["What's needed before starting"],
        "resources": ["Additional resources or documentation links"]
      }`;

      // the newest OpenAI model is "gpt-4o" which was released May 13, 2024. do not change this unless explicitly requested by the user
      const response = await openai.chat.completions.create({
        model: "gpt-4o",
        messages: [
          {
            role: "system",
            content: "You are an AWS security expert. Generate comprehensive, practical security playbooks in JSON format."
          },
          {
            role: "user",
            content: prompt
          }
        ],
        response_format: { type: "json_object" },
      });

      const playbookData = JSON.parse(response.choices[0].message.content || "{}");
      
      // Save the generated playbook
      const savedPlaybook = await storage.createPlaybook({
        title: playbookData.title,
        description: playbookData.description,
        type: playbookData.type,
        steps: playbookData.steps,
        estimatedTime: playbookData.estimatedTime,
        difficulty: playbookData.difficulty,
        status: "ready",
      });

      res.json(savedPlaybook);
    } catch (error: any) {
      console.error("Playbook generation error:", error);
      res.status(500).json({ error: "Failed to generate playbook. Please check your OpenAI API key." });
    }
  });

  // Generate security reports with AI insights
  app.post("/api/reports/generate", async (req, res) => {
    try {
      const { accountId } = req.body;
      
      const account = await storage.getAccountByAccountId(accountId);
      if (!account) {
        return res.status(404).json({ error: "Account not found" });
      }

      const findings = await storage.getSecurityFindingsByAccount(accountId);
      
      const prompt = `Generate an AI security summary for AWS account "${account.name}" with the following data:
      - Security Score: ${account.securityScore}/100
      - Critical Findings: ${account.criticalFindings}
      - High Risk Findings: ${account.highFindings}
      - Medium Risk Findings: ${account.mediumFindings}
      - Compliance Score: ${account.complianceScore}%
      
      Security Findings:
      ${findings.map(f => `- ${f.title} (${f.severity}): ${f.description}`).join('\n')}
      
      Provide a concise, business-friendly summary (2-3 sentences) that:
      1. Summarizes the security posture
      2. Highlights key risks or positive aspects
      3. Suggests impact of addressing findings
      
      Write as if explaining to a non-security stakeholder.`;

      // the newest OpenAI model is "gpt-4o" which was released May 13, 2024. do not change this unless explicitly requested by the user
      const response = await openai.chat.completions.create({
        model: "gpt-4o",
        messages: [
          {
            role: "system",
            content: "You are an AI security analyst. Generate clear, business-friendly security summaries."
          },
          {
            role: "user",
            content: prompt
          }
        ],
        max_tokens: 300,
      });

      const aiSummary = response.choices[0].message.content;
      
      res.json({
        account,
        findings,
        aiSummary,
        generatedAt: new Date(),
      });
    } catch (error: any) {
      console.error("Report generation error:", error);
      res.status(500).json({ error: "Failed to generate security report. Please check your OpenAI API key." });
    }
  });

  const httpServer = createServer(app);
  return httpServer;
}
