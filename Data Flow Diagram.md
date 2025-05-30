%% Level 0 - Context Diagram
graph TD
    A[👤 Users <br/> (Account Owners, Developers, Security Teams)]
    B(SecureAI Platform <br/> Cloud Security Democratization)
    C[🤖 OpenAI GPT-4o <br/> (External AI Service)]
    D[☁️ AWS Services <br/> (Security Hub, GuardDuty, IAM, Config)]

    A -- User Input & Queries --> B
    B -- AI Prompts --> C
    C -- AI Responses & Explanations --> B
    B -- Data Requests --> D
    D -- Security Data & Metrics --> B
    B -- Security Insights & Reports --> A
```mermaid
%% Level 1 - SecureAI Platform Breakdown
graph TD
    subgraph UserInteraction ["User Interaction Layer"]
        User["👤 Users"]
    end

    subgraph Frontend ["🎨 Frontend (React App)"]
        UI["SecureAI Web Interface <br/> (Dashboard, Policy Copilot, Chat, etc.)"]
    end

    subgraph Backend ["🔌 Backend API (Express.js)"]
        API["API Endpoints <br/> (/api/...)"]
        SecurityMiddleware["🛡️ Security Middleware <br/> (Auth, Rate Limit, Validation)"]
    end

    subgraph Logic ["🧠 Business Logic & AI Integration"]
        PolicyEngine["🔍 Policy Explanation Engine"]
        RemediationEngine["🛠️ Remediation Logic"]
        ReportEngine["📊 Report Generation Engine"]
        ChatEngine["💬 Chat Processing Engine"]
        PlaybookEngine["📋 Playbook Logic"]
    end

    subgraph DataStorage ["🗄️ Data Storage (PostgreSQL)"]
        DS_Users["👥 Users Table"]
        DS_Accounts["🏢 Accounts Table"]
        DS_Findings["🚨 Security Findings Table"]
        DS_Messages["💬 Chat Messages Table"]
        DS_Playbooks["📚 Playbooks Table"]
        DS_Audit["📝 Audit Logs Table"]
    end

    subgraph ExternalServices ["🌐 External Services"]
        OpenAI["🤖 OpenAI GPT-4o"]
        AWSServices["☁️ AWS Services <br/> (Security Hub, GuardDuty, etc.)"]
    end

    %% Data Flows
    User -- User Actions & Data Input --> UI
    UI -- API Requests (HTTPS) --> SecurityMiddleware
    SecurityMiddleware -- Validated Requests --> API

    API -- Invoke Dashboard Logic --> ReportEngine
    API -- Invoke Policy Explanation --> PolicyEngine
    API -- Invoke Remediation Logic --> RemediationEngine
    API -- Invoke Chat Logic --> ChatEngine
    API -- Invoke Playbook Logic --> PlaybookEngine

    PolicyEngine -- Prompts for Explanation --> OpenAI
    OpenAI -- Policy Explanation --> PolicyEngine
    PolicyEngine -- Formatted Explanation --> API

    RemediationEngine -- Prompts for Guidance --> OpenAI
    OpenAI -- Remediation Steps --> RemediationEngine
    RemediationEngine -- Structured Guidance --> API

    ReportEngine -- Prompts for Summary --> OpenAI
    OpenAI -- AI Summary --> ReportEngine
    ReportEngine -- Security Data Query --> DS_Accounts
    ReportEngine -- Security Data Query --> DS_Findings
    DS_Accounts -- Account Data --> ReportEngine
    DS_Findings -- Findings Data --> ReportEngine
    ReportEngine -- Compiled Report Data --> API

    ChatEngine -- Prompts for Response --> OpenAI
    OpenAI -- Chat Response --> ChatEngine
    ChatEngine -- Store User Message --> DS_Messages
    ChatEngine -- Store AI Response --> DS_Messages
    DS_Messages -- Chat History --> ChatEngine
    ChatEngine -- Chat Data --> API

    PlaybookEngine -- Prompts for Playbook --> OpenAI
    OpenAI -- Playbook Structure --> PlaybookEngine
    PlaybookEngine -- Store Playbook --> DS_Playbooks
    DS_Playbooks -- Playbook Data --> PlaybookEngine
    PlaybookEngine -- Playbook Info --> API

    API -- Data Operations (CRUD) --> DS_Users
    API -- Data Operations (CRUD) --> DS_Accounts
    API -- Data Operations (CRUD) --> DS_Findings
    API -- Data Operations (CRUD) --> DS_Playbooks
    API -- Log Actions --> DS_Audit

    %% AWS Services Data Ingestion (Conceptual - could be batch or real-time)
    AWSServices -- Security Data (Findings, Metrics) --> DataStorage

    API -- API Responses (JSON) --> UI
    UI -- Display Data & Insights --> User

    %% Styling
    classDef user fill:#e1f5fe,stroke:#01579b,stroke-width:2px
    classDef frontend fill:#f3e5f5,stroke:#4a148c,stroke-width:2px
    classDef backend fill:#e8f5e8,stroke:#1b5e20,stroke-width:2px
    classDef logic fill:#fff3e0,stroke:#e65100,stroke-width:2px
    classDef datastorage fill:#e3f2fd,stroke:#0d47a1,stroke-width:2px
    classDef external fill:#fce4ec,stroke:#880e4f,stroke-width:2px

    class User user
    class UI frontend
    class API,SecurityMiddleware backend
    class PolicyEngine,RemediationEngine,ReportEngine,ChatEngine,PlaybookEngine logic
    class DS_Users,DS_Accounts,DS_Findings,DS_Messages,DS_Playbooks,DS_Audit datastorage
    class OpenAI,AWSServices external
