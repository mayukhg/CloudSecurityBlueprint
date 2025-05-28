import { Link, useLocation } from "wouter";
import { cn } from "@/lib/utils";
import { 
  Shield, 
  BarChart3, 
  Languages, 
  Wrench, 
  MessageSquare, 
  BookOpen,
  TrendingUp 
} from "lucide-react";

const navigation = [
  { name: "Dashboard", href: "/", icon: BarChart3 },
  { name: "Policy Copilot", href: "/policy-copilot", icon: Languages },
  { name: "Remediation Assistant", href: "/remediation", icon: Wrench },
  { name: "Security Reports", href: "/reports", icon: TrendingUp },
  { name: "Security Concierge", href: "/chat", icon: MessageSquare },
  { name: "Playbooks", href: "/playbooks", icon: BookOpen },
];

export default function Sidebar() {
  const [location] = useLocation();

  return (
    <aside className="w-64 bg-white shadow-lg border-r border-gray-200 fixed h-full z-10">
      <div className="p-6">
        <div className="flex items-center space-x-3 mb-8">
          <div className="w-10 h-10 bg-primary rounded-lg flex items-center justify-center">
            <Shield className="h-6 w-6 text-white" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-gray-900">SecureAI</h1>
            <p className="text-sm text-gray-500">Cloud Security Platform</p>
          </div>
        </div>
        
        <nav className="space-y-2">
          {navigation.map((item) => {
            const isActive = location === item.href;
            return (
              <Link
                key={item.name}
                href={item.href}
                className={cn(
                  "flex items-center space-x-3 px-4 py-3 rounded-lg font-medium transition-colors",
                  isActive
                    ? "text-primary bg-blue-50"
                    : "text-gray-600 hover:bg-gray-50"
                )}
              >
                <item.icon className="h-5 w-5" />
                <span>{item.name}</span>
              </Link>
            );
          })}
        </nav>
      </div>
    </aside>
  );
}
