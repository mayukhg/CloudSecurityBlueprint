import { useQuery } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Link } from "wouter";
import { 
  Cloud, 
  AlertTriangle, 
  CheckCircle, 
  Bot,
  Languages,
  Wrench,
  MessageSquare,
  ArrowRight,
  TrendingUp,
  TrendingDown,
  BookOpen
} from "lucide-react";

interface DashboardData {
  totalAccounts: number;
  criticalFindings: number;
  complianceScore: number;
  aiResolutions: number;
}

interface SecurityFinding {
  id: number;
  accountId: string;
  title: string;
  description: string;
  severity: string;
  status: string;
  service: string;
}

export default function Dashboard() {
  const { data: overview, isLoading: overviewLoading } = useQuery<DashboardData>({
    queryKey: ["/api/dashboard/overview"],
  });

  const { data: findings, isLoading: findingsLoading } = useQuery<SecurityFinding[]>({
    queryKey: ["/api/security-findings"],
  });

  const topFindings = findings?.slice(0, 3) || [];

  const severityColors = {
    critical: "bg-red-100 text-red-800",
    high: "bg-orange-100 text-orange-800",
    medium: "bg-yellow-100 text-yellow-800",
    low: "bg-gray-100 text-gray-800",
  };

  const statusColors = {
    open: "bg-gray-100 text-gray-800",
    in_progress: "bg-yellow-100 text-yellow-800",
    resolved: "bg-green-100 text-green-800",
  };

  if (overviewLoading || findingsLoading) {
    return (
      <div className="p-8">
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
          {[...Array(4)].map((_, i) => (
            <Card key={i} className="animate-pulse">
              <CardContent className="p-6">
                <div className="h-16 bg-gray-200 rounded"></div>
              </CardContent>
            </Card>
          ))}
        </div>
      </div>
    );
  }

  return (
    <div className="p-8">
      {/* Security Overview Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
        <Card>
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-gray-500 text-sm font-medium">Total Accounts</p>
                <p className="text-3xl font-bold text-gray-900">{overview?.totalAccounts || 0}</p>
              </div>
              <div className="w-12 h-12 bg-blue-100 rounded-lg flex items-center justify-center">
                <Cloud className="h-6 w-6 text-primary" />
              </div>
            </div>
            <div className="mt-4 flex items-center">
              <TrendingUp className="h-4 w-4 text-green-500 mr-1" />
              <span className="text-green-500 text-sm font-medium">+5% from last month</span>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-gray-500 text-sm font-medium">Critical Findings</p>
                <p className="text-3xl font-bold text-red-600">{overview?.criticalFindings || 0}</p>
              </div>
              <div className="w-12 h-12 bg-red-100 rounded-lg flex items-center justify-center">
                <AlertTriangle className="h-6 w-6 text-red-600" />
              </div>
            </div>
            <div className="mt-4 flex items-center">
              <TrendingDown className="h-4 w-4 text-green-500 mr-1" />
              <span className="text-green-500 text-sm font-medium">-12% from last week</span>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-gray-500 text-sm font-medium">Compliance Score</p>
                <p className="text-3xl font-bold text-green-600">{overview?.complianceScore || 0}%</p>
              </div>
              <div className="w-12 h-12 bg-green-100 rounded-lg flex items-center justify-center">
                <CheckCircle className="h-6 w-6 text-green-600" />
              </div>
            </div>
            <div className="mt-4 flex items-center">
              <TrendingUp className="h-4 w-4 text-green-500 mr-1" />
              <span className="text-green-500 text-sm font-medium">+3% improvement</span>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-gray-500 text-sm font-medium">AI Resolutions</p>
                <p className="text-3xl font-bold text-orange-600">{overview?.aiResolutions || 0}</p>
              </div>
              <div className="w-12 h-12 bg-orange-100 rounded-lg flex items-center justify-center">
                <Bot className="h-6 w-6 text-orange-600" />
              </div>
            </div>
            <div className="mt-4 flex items-center">
              <span className="text-orange-600 text-sm font-medium">This month</span>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Quick Actions and Recent Activity */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 mb-8">
        <Card>
          <CardHeader>
            <CardTitle>Quick Actions</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <Link href="/policy-copilot">
              <Button
                variant="ghost"
                className="w-full justify-between p-4 h-auto bg-blue-50 hover:bg-blue-100 text-left"
              >
                <div className="flex items-center space-x-3">
                  <Languages className="h-5 w-5 text-primary" />
                  <span className="font-medium text-gray-900">Explain Security Policy</span>
                </div>
                <ArrowRight className="h-4 w-4 text-gray-400" />
              </Button>
            </Link>
            <Link href="/remediation">
              <Button
                variant="ghost"
                className="w-full justify-between p-4 h-auto bg-green-50 hover:bg-green-100 text-left"
              >
                <div className="flex items-center space-x-3">
                  <Wrench className="h-5 w-5 text-green-600" />
                  <span className="font-medium text-gray-900">Get Remediation Help</span>
                </div>
                <ArrowRight className="h-4 w-4 text-gray-400" />
              </Button>
            </Link>
            <Link href="/chat">
              <Button
                variant="ghost"
                className="w-full justify-between p-4 h-auto bg-orange-50 hover:bg-orange-100 text-left"
              >
                <div className="flex items-center space-x-3">
                  <MessageSquare className="h-5 w-5 text-orange-600" />
                  <span className="font-medium text-gray-900">Ask Security Question</span>
                </div>
                <ArrowRight className="h-4 w-4 text-gray-400" />
              </Button>
            </Link>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Recent AI Activity</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex items-start space-x-3">
              <div className="w-8 h-8 bg-blue-100 rounded-full flex items-center justify-center flex-shrink-0">
                <Bot className="h-4 w-4 text-primary" />
              </div>
              <div className="flex-1 min-w-0">
                <p className="text-sm font-medium text-gray-900">Policy translated for Account-4472</p>
                <p className="text-xs text-gray-500">2 minutes ago</p>
              </div>
            </div>
            <div className="flex items-start space-x-3">
              <div className="w-8 h-8 bg-green-100 rounded-full flex items-center justify-center flex-shrink-0">
                <CheckCircle className="h-4 w-4 text-green-600" />
              </div>
              <div className="flex-1 min-w-0">
                <p className="text-sm font-medium text-gray-900">Remediation completed for S3 bucket exposure</p>
                <p className="text-xs text-gray-500">15 minutes ago</p>
              </div>
            </div>
            <div className="flex items-start space-x-3">
              <div className="w-8 h-8 bg-orange-100 rounded-full flex items-center justify-center flex-shrink-0">
                <BookOpen className="h-4 w-4 text-orange-600" />
              </div>
              <div className="flex-1 min-w-0">
                <p className="text-sm font-medium text-gray-900">Playbook generated for new account setup</p>
                <p className="text-xs text-gray-500">1 hour ago</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Top Security Findings */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle>Top Security Findings</CardTitle>
            <Button variant="ghost" className="text-primary">View All</Button>
          </div>
        </CardHeader>
        <CardContent>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-gray-200">
                  <th className="text-left py-3 px-4 font-medium text-gray-500">Account</th>
                  <th className="text-left py-3 px-4 font-medium text-gray-500">Finding</th>
                  <th className="text-left py-3 px-4 font-medium text-gray-500">Severity</th>
                  <th className="text-left py-3 px-4 font-medium text-gray-500">Status</th>
                  <th className="text-left py-3 px-4 font-medium text-gray-500">Action</th>
                </tr>
              </thead>
              <tbody>
                {topFindings.map((finding) => (
                  <tr key={finding.id} className="border-b border-gray-100">
                    <td className="py-3 px-4 text-sm text-gray-900">{finding.accountId}</td>
                    <td className="py-3 px-4 text-sm text-gray-900">{finding.title}</td>
                    <td className="py-3 px-4">
                      <Badge 
                        className={`${severityColors[finding.severity as keyof typeof severityColors]} capitalize`}
                      >
                        {finding.severity}
                      </Badge>
                    </td>
                    <td className="py-3 px-4">
                      <Badge 
                        className={`${statusColors[finding.status as keyof typeof statusColors]} capitalize`}
                      >
                        {finding.status.replace('_', ' ')}
                      </Badge>
                    </td>
                    <td className="py-3 px-4">
                      <Link href="/remediation">
                        <Button variant="ghost" size="sm" className="text-primary">
                          Get Fix
                        </Button>
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
