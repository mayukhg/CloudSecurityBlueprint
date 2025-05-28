# SecureAI Platform - Architecture Diagram

```mermaid
graph TB
    %% User Layer
    User[👤 Non-Technical Users<br/>Account Owners, Developers]
    DevTeam[👥 Development Team<br/>DevOps Engineers]
    
    %% CI/CD Pipeline Layer
    subgraph "CI/CD Pipeline (AWS CodePipeline)"
        GitHub[📱 GitHub Repository<br/>Source Code & Webhook]
        CodeBuild[🔨 AWS CodeBuild<br/>Build, Test & Docker]
        ECR[📦 Amazon ECR<br/>Container Registry]
        Pipeline[🔄 CodePipeline<br/>Automated Workflow]
        Approval[✋ Manual Approval<br/>Production Gate]
    end
    
    %% Infrastructure Layer
    subgraph "AWS Infrastructure (CloudFormation)"
        VPC[🌐 VPC<br/>Network Security]
        ALB[⚖️ Application Load Balancer<br/>High Availability]
        ECS[🐳 ECS Fargate<br/>Container Orchestration]
        RDS[🗄️ PostgreSQL RDS<br/>Managed Database]
        Secrets[🔐 Secrets Manager<br/>Secure Configuration]
        CloudWatch[📊 CloudWatch<br/>Monitoring & Logs]
    end
    
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
        HealthAPI[/health<br/>Health Check Endpoint]
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
    
    %% AWS Integration
    subgraph "AWS Services (Security Data Sources)"
        SecurityHub[🛡️ Security Hub<br/>Findings Import]
        GuardDuty[🔍 GuardDuty<br/>Threat Detection]
        IAM[🔐 IAM<br/>Policy Analysis]
        Config[⚙️ Config<br/>Compliance Rules]
    end
    
    %% CI/CD Flow
    DevTeam --> GitHub
    GitHub --> Pipeline
    Pipeline --> CodeBuild
    CodeBuild --> ECR
    ECR --> ECS
    
    %% Infrastructure Flow
    ALB --> ECS
    ECS --> RDS
    ECS --> Secrets
    CloudWatch --> ECS
    VPC --> ALB
    VPC --> ECS
    VPC --> RDS
    
    %% Application Flow
    User --> ALB
    ALB --> Dashboard
    ALB --> PolicyCopilot
    ALB --> Remediation
    ALB --> Reports
    ALB --> Chat
    ALB --> Playbooks
    
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
    HealthAPI --> Storage
    
    Storage --> Users
    Storage --> Accounts
    Storage --> Findings
    Storage --> Messages
    Storage --> PlaybookDB
    
    %% AWS Service Integrations
    SecurityHub --> Findings
    GuardDuty --> Findings
    IAM --> AIAPI
    Config --> Accounts
    
    %% Production Gates
    Pipeline --> Approval
    Approval --> ECS
    
    %% Monitoring
    CloudWatch --> Pipeline
    CloudWatch --> ALB
    CloudWatch --> RDS
    
    %% Styling
    classDef userClass fill:#e1f5fe,stroke:#01579b,stroke-width:2px
    classDef cicdClass fill:#fff3e0,stroke:#e65100,stroke-width:2px
    classDef infraClass fill:#f1f8e9,stroke:#33691e,stroke-width:2px
    classDef frontendClass fill:#f3e5f5,stroke:#4a148c,stroke-width:2px
    classDef apiClass fill:#e8f5e8,stroke:#1b5e20,stroke-width:2px
    classDef storageClass fill:#fff3e0,stroke:#e65100,stroke-width:2px
    classDef aiClass fill:#fce4ec,stroke:#880e4f,stroke-width:2px
    classDef dbClass fill:#e3f2fd,stroke:#0d47a1,stroke-width:2px
    classDef awsClass fill:#f1f8e9,stroke:#33691e,stroke-width:2px
    
    class User,DevTeam userClass
    class GitHub,CodeBuild,ECR,Pipeline,Approval cicdClass
    class VPC,ALB,ECS,RDS,Secrets,CloudWatch infraClass
    class Dashboard,PolicyCopilot,Remediation,Reports,Chat,Playbooks frontendClass
    class DashboardAPI,AIAPI,ChatAPI,PlaybookAPI,HealthAPI apiClass
    class Storage storageClass
    class OpenAI aiClass
    class Users,Accounts,Findings,Messages,PlaybookDB dbClass
    class SecurityHub,GuardDuty,IAM,Config awsClass
```

## Architecture Components

### 👥 User Layer
- **Non-Technical Users**: Account owners, developers, and business stakeholders using the platform
- **Development Team**: DevOps engineers managing CI/CD pipeline and infrastructure

### 🔄 CI/CD Pipeline Layer (AWS CodePipeline)
- **GitHub Repository**: Source code management with webhook integration
- **AWS CodeBuild**: Automated build, test, and Docker containerization
- **Amazon ECR**: Secure container image registry with vulnerability scanning
- **CodePipeline**: Complete workflow automation from code to deployment
- **Manual Approval**: Production deployment gate with email notifications

### 🏗️ AWS Infrastructure Layer (CloudFormation)
- **VPC**: Secure network isolation with public/private subnets
- **Application Load Balancer**: High availability with SSL/TLS termination
- **ECS Fargate**: Serverless container orchestration with auto-scaling
- **PostgreSQL RDS**: Managed database with automated backups and encryption
- **Secrets Manager**: Secure storage for API keys and database credentials
- **CloudWatch**: Comprehensive monitoring, logging, and alerting

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
- **Health API**: Load balancer health checks and monitoring

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

### ☁️ AWS Security Data Sources
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