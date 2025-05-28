# SecureAI Platform - Architecture Diagram

```mermaid
graph TB
    %% User Layer
    User[👤 Non-Technical Users<br/>Account Owners, Developers]
    
    %% Frontend Layer
    subgraph "Frontend (React + TypeScript)"
        Dashboard[📊 Dashboard<br/>Multi-Account Overview]
        PolicyCopilot[🔍 Policy Copilot<br/>AI Policy Explanation]
        Remediation[🛠️ Remediation Assistant<br/>Step-by-Step Fixes]
        Reports[📈 Security Reports<br/>AI-Generated Insights]
        Chat[💬 Security Concierge<br/>AI Chat Assistant]
        Playbooks[📋 Playbook Generator<br/>Automated Procedures]
    end
    
    %% API Layer
    subgraph "Backend API (Express + TypeScript)"
        DashboardAPI[/api/dashboard/overview<br/>/api/accounts<br/>/api/security-findings]
        AIAPI[/api/policy-copilot/explain<br/>/api/remediation/steps<br/>/api/reports/generate]
        ChatAPI[/api/chat/messages<br/>/api/chat/message]
        PlaybookAPI[/api/playbooks<br/>/api/playbooks/generate]
    end
    
    %% Business Logic Layer
    subgraph "Data Access Layer"
        Storage[🗄️ DatabaseStorage<br/>Repository Pattern<br/>Type-Safe Operations]
    end
    
    %% External Services
    subgraph "AI Services"
        OpenAI[🤖 OpenAI GPT-4o<br/>Policy Explanations<br/>Remediation Guidance<br/>Chat Responses<br/>Report Generation]
    end
    
    %% Database Layer
    subgraph "PostgreSQL Database"
        Users[(👥 users<br/>Authentication)]
        Accounts[(🏢 accounts<br/>AWS Account Metrics)]
        Findings[(🚨 security_findings<br/>Vulnerabilities)]
        Messages[(💬 chat_messages<br/>Conversation History)]
        PlaybookDB[(📚 playbooks<br/>Security Procedures)]
    end
    
    %% AWS Integration (Future)
    subgraph "AWS Services (Integration Points)"
        SecurityHub[🛡️ Security Hub<br/>Findings Import]
        GuardDuty[🔍 GuardDuty<br/>Threat Detection]
        IAM[🔐 IAM<br/>Policy Analysis]
        Config[⚙️ Config<br/>Compliance Rules]
    end
    
    %% Data Flow Connections
    User --> Dashboard
    User --> PolicyCopilot
    User --> Remediation
    User --> Reports
    User --> Chat
    User --> Playbooks
    
    Dashboard --> DashboardAPI
    PolicyCopilot --> AIAPI
    Remediation --> AIAPI
    Reports --> AIAPI
    Chat --> ChatAPI
    Playbooks --> PlaybookAPI
    
    DashboardAPI --> Storage
    AIAPI --> Storage
    AIAPI --> OpenAI
    ChatAPI --> Storage
    ChatAPI --> OpenAI
    PlaybookAPI --> Storage
    PlaybookAPI --> OpenAI
    
    Storage --> Users
    Storage --> Accounts
    Storage --> Findings
    Storage --> Messages
    Storage --> PlaybookDB
    
    %% Future integrations (dotted lines)
    SecurityHub -.-> Findings
    GuardDuty -.-> Findings
    IAM -.-> AIAPI
    Config -.-> Accounts
    
    %% Styling
    classDef userClass fill:#e1f5fe,stroke:#01579b,stroke-width:2px
    classDef frontendClass fill:#f3e5f5,stroke:#4a148c,stroke-width:2px
    classDef apiClass fill:#e8f5e8,stroke:#1b5e20,stroke-width:2px
    classDef storageClass fill:#fff3e0,stroke:#e65100,stroke-width:2px
    classDef aiClass fill:#fce4ec,stroke:#880e4f,stroke-width:2px
    classDef dbClass fill:#e3f2fd,stroke:#0d47a1,stroke-width:2px
    classDef awsClass fill:#f1f8e9,stroke:#33691e,stroke-width:2px
    
    class User userClass
    class Dashboard,PolicyCopilot,Remediation,Reports,Chat,Playbooks frontendClass
    class DashboardAPI,AIAPI,ChatAPI,PlaybookAPI apiClass
    class Storage storageClass
    class OpenAI aiClass
    class Users,Accounts,Findings,Messages,PlaybookDB dbClass
    class SecurityHub,GuardDuty,IAM,Config awsClass
```

## Architecture Components

### 🎨 Frontend Layer (React + TypeScript)
- **Dashboard**: Multi-account security overview with metrics and quick actions
- **Policy Copilot**: AI-powered policy explanation interface
- **Remediation Assistant**: Step-by-step security issue resolution
- **Security Reports**: AI-generated account-specific insights
- **Security Concierge**: Real-time chat with AI security expert
- **Playbook Generator**: Automated security procedure creation

### 🔗 API Layer (Express + TypeScript)
- **Dashboard APIs**: Account metrics and security findings endpoints
- **AI APIs**: OpenAI integration for explanations, remediation, and reports
- **Chat APIs**: Conversation management and AI response handling
- **Playbook APIs**: Security procedure generation and storage

### 🗄️ Data Access Layer
- **DatabaseStorage**: Repository pattern implementation
- **Type-Safe Operations**: Drizzle ORM with full TypeScript support
- **Connection Pooling**: Efficient database connection management

### 🤖 AI Services Integration
- **OpenAI GPT-4o**: Latest AI model for optimal responses
- **Policy Explanations**: Complex security policies in plain English
- **Remediation Guidance**: Step-by-step fix instructions
- **Chat Responses**: Contextual security assistance
- **Report Generation**: Business-friendly security summaries

### 🗃️ Database Layer (PostgreSQL)
- **users**: Authentication and user management
- **accounts**: AWS account information and security metrics
- **security_findings**: Individual vulnerabilities and issues
- **chat_messages**: AI conversation history
- **playbooks**: Generated security procedures

### ☁️ AWS Integration Points (Future)
- **Security Hub**: Centralized security findings import
- **GuardDuty**: Threat detection integration
- **IAM**: Policy analysis and recommendations
- **Config**: Compliance rule monitoring

## Data Flow

1. **User Interaction**: Non-technical users interact with intuitive frontend interfaces
2. **API Processing**: Express.js APIs handle requests with proper validation
3. **AI Enhancement**: OpenAI GPT-4o provides intelligent insights and explanations
4. **Data Persistence**: PostgreSQL stores all platform data persistently
5. **Real-time Updates**: React Query ensures UI stays synchronized with backend

## Security Architecture

- **Environment Variables**: All secrets stored securely
- **Server-Side AI Calls**: API keys never exposed to client
- **Input Validation**: Zod schemas validate all requests
- **Type Safety**: TypeScript prevents runtime errors
- **SQL Injection Prevention**: Drizzle ORM parameterized queries

## Scalability Design

- **Serverless Ready**: Compatible with modern deployment platforms
- **Connection Pooling**: Efficient database resource utilization
- **Caching Strategy**: React Query reduces unnecessary API calls
- **Modular Architecture**: Easy feature addition and maintenance