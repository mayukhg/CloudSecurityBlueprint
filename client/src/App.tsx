import { Switch, Route } from "wouter";
import { queryClient } from "./lib/queryClient";
import { QueryClientProvider } from "@tanstack/react-query";
import { Toaster } from "@/components/ui/toaster";
import { TooltipProvider } from "@/components/ui/tooltip";
import Sidebar from "@/components/sidebar";
import Header from "@/components/header";
import Dashboard from "@/pages/dashboard";
import PolicyCopilot from "@/pages/policy-copilot";
import Remediation from "@/pages/remediation";
import Reports from "@/pages/reports";
import Chat from "@/pages/chat";
import Playbooks from "@/pages/playbooks";
import NotFound from "@/pages/not-found";

const pageConfig = {
  "/": {
    title: "Security Dashboard",
    subtitle: "Monitor and manage security across your AWS accounts",
    component: Dashboard,
  },
  "/policy-copilot": {
    title: "Security Policy Copilot",
    subtitle: "Translate complex policies into plain English",
    component: PolicyCopilot,
  },
  "/remediation": {
    title: "Remediation Assistant",
    subtitle: "Get step-by-step guidance to fix security issues",
    component: Remediation,
  },
  "/reports": {
    title: "Security Reports",
    subtitle: "AI-generated insights for your security posture",
    component: Reports,
  },
  "/chat": {
    title: "Security Concierge",
    subtitle: "Ask questions about your AWS security",
    component: Chat,
  },
  "/playbooks": {
    title: "Security Playbooks",
    subtitle: "Automated procedures for common security tasks",
    component: Playbooks,
  },
};

function Router() {
  return (
    <div className="min-h-screen flex bg-gray-50">
      <Sidebar />
      <main className="flex-1 ml-64">
        <Switch>
          {Object.entries(pageConfig).map(([path, config]) => (
            <Route key={path} path={path}>
              <Header title={config.title} subtitle={config.subtitle} />
              <config.component />
            </Route>
          ))}
          <Route component={NotFound} />
        </Switch>
      </main>
    </div>
  );
}

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <TooltipProvider>
        <Toaster />
        <Router />
      </TooltipProvider>
    </QueryClientProvider>
  );
}

export default App;
