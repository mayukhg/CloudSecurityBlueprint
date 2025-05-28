# SecureAI - Cloud Security Democratization Platform

An AI-powered platform that democratizes cloud security across AWS accounts by providing natural language explanations, automated guidance, and intelligent insights for non-security stakeholders.

## 🚀 Features

### 1. Security Policy Copilot
- **Plain English Explanations**: Translates complex security policies (IAM, SCPs, etc.) into understandable language
- **Interactive Interface**: Simple textarea input with AI-powered analysis
- **Example Policies**: Pre-loaded examples for quick testing

### 2. Remediation Assistant
- **Step-by-Step Guidance**: Detailed remediation steps for common security issues
- **Multiple Formats**: Both AWS CLI commands and console instructions
- **Progress Tracking**: Mark steps as complete and track remediation progress
- **Difficulty Indicators**: Easy, medium, or hard classification for each fix

### 3. AI Security Reports
- **Account-Specific Insights**: Generate intelligent summaries for each AWS account
- **Business-Friendly Language**: Non-technical explanations of security posture
- **Visual Metrics**: Security scores, compliance ratings, and finding breakdowns
- **Trend Analysis**: Progress tracking and improvement recommendations

### 4. Security Concierge Chat
- **Real-Time Assistance**: Chat-based security support powered by AI
- **Context-Aware Responses**: Understands your specific AWS environment
- **Quick Questions**: Pre-defined common queries for instant answers
- **Session Persistence**: Chat history saved for continuity

### 5. Automated Playbook Generator
- **Custom Procedures**: Generate security playbooks for various scenarios
- **Requirement-Based**: Tailored to your specific organizational needs
- **Multiple Types**: New account setup, incident response, compliance audits
- **Reusable Templates**: Save and reuse generated playbooks

### 6. Comprehensive Dashboard
- **Multi-Account Overview**: Monitor security across all AWS accounts
- **Key Metrics**: Critical findings, compliance scores, AI resolutions
- **Quick Actions**: Direct access to all platform features
- **Recent Activity**: Real-time updates on AI-assisted security actions

## 🏗️ Architecture

### Frontend (`/client`)
- **Framework**: React with TypeScript
- **Routing**: Wouter for lightweight client-side routing
- **UI Components**: Shadcn/ui with Tailwind CSS
- **State Management**: TanStack Query for server state
- **Icons**: Lucide React for consistent iconography

### Backend (`/server`)
- **Runtime**: Node.js with Express
- **Database**: PostgreSQL with Drizzle ORM
- **AI Integration**: OpenAI GPT-4o for intelligent features
- **API Design**: RESTful endpoints with TypeScript

### Database Schema (`/shared`)
- **Users**: Authentication and user management
- **Accounts**: AWS account information and metrics
- **Security Findings**: Vulnerabilities and security issues
- **Chat Messages**: Conversation history for the concierge
- **Playbooks**: Generated security procedures

## 📁 Project Structure

```
├── client/                 # Frontend React application
│   ├── src/
│   │   ├── components/     # Reusable UI components
│   │   │   ├── ui/         # Shadcn/ui components
│   │   │   ├── header.tsx  # Application header
│   │   │   └── sidebar.tsx # Navigation sidebar
│   │   ├── pages/          # Application pages/routes
│   │   │   ├── dashboard.tsx
│   │   │   ├── policy-copilot.tsx
│   │   │   ├── remediation.tsx
│   │   │   ├── reports.tsx
│   │   │   ├── chat.tsx
│   │   │   └── playbooks.tsx
│   │   ├── lib/            # Utility libraries
│   │   │   ├── queryClient.ts
│   │   │   ├── openai.ts   # AI-related types
│   │   │   └── utils.ts
│   │   ├── hooks/          # Custom React hooks
│   │   ├── App.tsx         # Main application component
│   │   └── main.tsx        # Application entry point
│   └── index.html          # HTML template
├── server/                 # Backend Express application
│   ├── index.ts           # Server entry point
│   ├── routes.ts          # API route definitions
│   ├── storage.ts         # Database operations
│   ├── db.ts              # Database connection
│   └── vite.ts            # Development server setup
├── shared/                 # Shared types and schemas
│   └── schema.ts          # Database schema and types
├── drizzle.config.ts      # Database configuration
├── package.json           # Dependencies and scripts
└── tailwind.config.ts     # Styling configuration
```

## 🛠️ Technology Stack

### Core Technologies
- **TypeScript**: Full-stack type safety
- **React 18**: Modern React with hooks
- **Express**: Fast, minimalist web framework
- **PostgreSQL**: Reliable relational database
- **Drizzle ORM**: Type-safe database operations

### Development Tools
- **Vite**: Fast build tool and dev server
- **Tailwind CSS**: Utility-first CSS framework
- **ESBuild**: Fast JavaScript bundler
- **TSX**: TypeScript execution for Node.js

### AI & External Services
- **OpenAI GPT-4o**: Latest AI model for intelligent features
- **Neon Serverless**: Serverless PostgreSQL hosting

## 🚦 Getting Started

### Prerequisites
- Node.js 20+
- PostgreSQL database
- OpenAI API key

### Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd secureai-platform
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Set up environment variables**
   ```bash
   # Required environment variables
   DATABASE_URL=postgresql://username:password@host:port/database
   OPENAI_API_KEY=your_openai_api_key_here
   ```

4. **Initialize the database**
   ```bash
   npm run db:push
   ```

5. **Start the development server**
   ```bash
   npm run dev
   ```

6. **Access the application**
   - Open your browser to `http://localhost:5000`

## 📚 API Endpoints

### Dashboard
- `GET /api/dashboard/overview` - Get security overview statistics
- `GET /api/accounts` - List all AWS accounts
- `GET /api/security-findings` - Get security findings (optionally filtered by account)

### AI Features
- `POST /api/policy-copilot/explain` - Explain security policies in plain English
- `POST /api/remediation/steps` - Generate step-by-step remediation guidance
- `POST /api/reports/generate` - Create AI-powered security reports

### Chat System
- `GET /api/chat/messages/:sessionId` - Get chat history for a session
- `POST /api/chat/message` - Send a message and get AI response

### Playbooks
- `GET /api/playbooks` - List all saved playbooks
- `POST /api/playbooks/generate` - Generate new security playbooks

## 🔧 Configuration

### Database Configuration
The application uses Drizzle ORM with PostgreSQL. Database configuration is in `drizzle.config.ts`:

```typescript
export default {
  schema: "./shared/schema.ts",
  out: "./drizzle",
  driver: "pg",
  dbCredentials: {
    connectionString: process.env.DATABASE_URL!,
  },
} satisfies Config;
```

### AI Configuration
OpenAI integration is configured in the server routes with the latest GPT-4o model for optimal performance.

## 🎨 UI/UX Design

### Design System
- **Color Palette**: Professional blue (#1976D2) with semantic colors
- **Typography**: Inter font family for readability
- **Components**: Consistent design language using Shadcn/ui
- **Responsive**: Mobile-first design approach
- **Accessibility**: ARIA labels and semantic HTML

### User Experience
- **Intuitive Navigation**: Clear sidebar with feature-based organization
- **Progressive Disclosure**: Complex information presented in digestible chunks
- **Real-time Feedback**: Loading states and success/error messages
- **Quick Actions**: Shortcuts for common tasks

## 🔒 Security Considerations

### Data Protection
- Environment variables for sensitive configuration
- SQL injection protection through parameterized queries
- Input validation using Zod schemas

### API Security
- Request validation and sanitization
- Error handling without information leakage
- Rate limiting considerations for production

## 🚀 Deployment

### Production Checklist
- [ ] Set production environment variables
- [ ] Configure production database
- [ ] Set up monitoring and logging
- [ ] Configure HTTPS/SSL
- [ ] Set up backup strategies
- [ ] Implement rate limiting
- [ ] Configure error tracking

### Environment Variables
```bash
NODE_ENV=production
DATABASE_URL=your_production_database_url
OPENAI_API_KEY=your_openai_api_key
```

## 🧪 Development

### Available Scripts
- `npm run dev` - Start development server
- `npm run build` - Build for production
- `npm run db:push` - Push database schema changes
- `npm run db:generate` - Generate migration files

### Development Workflow
1. Make changes to the codebase
2. Test locally with `npm run dev`
3. Push database changes with `npm run db:push`
4. Commit and deploy changes

## 🤝 Contributing

### Code Style
- TypeScript for type safety
- ESLint for code quality
- Prettier for code formatting
- Consistent naming conventions

### Best Practices
- Component-based architecture
- Separation of concerns
- Error boundary implementation
- Performance optimization

## 📄 License

This project is private and proprietary. All rights reserved.

## 🆘 Support

For support and questions:
- Check the application logs for error details
- Verify environment variables are correctly set
- Ensure database connectivity
- Validate OpenAI API key functionality

---

**SecureAI Platform** - Democratizing cloud security through AI-powered insights and automation.