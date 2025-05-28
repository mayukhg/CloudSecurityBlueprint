import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Download, Bot, TrendingUp, AlertTriangle, CheckCircle } from "lucide-react";
import { apiRequest } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import type { Account } from "@shared/schema";

interface SecurityReport {
  account: Account;
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

const getRiskScoreColor = (score: number) => {
  if (score >= 90) return "text-green-600";
  if (score >= 75) return "text-yellow-600";
  if (score >= 60) return "text-orange-600";
  return "text-red-600";
};

const getRiskScoreBg = (score: number) => {
  if (score >= 90) return "bg-green-100";
  if (score >= 75) return "bg-yellow-100";
  if (score >= 60) return "bg-orange-100";
  return "bg-red-100";
};

const getProgressColor = (score: number) => {
  if (score >= 90) return "bg-green-500";
  if (score >= 75) return "bg-yellow-500";
  if (score >= 60) return "bg-orange-500";
  return "bg-red-500";
};

export default function Reports() {
  const [selectedTimeRange, setSelectedTimeRange] = useState("30");
  const [generatedReports, setGeneratedReports] = useState<SecurityReport[]>([]);
  const { toast } = useToast();

  const { data: accounts, isLoading: accountsLoading } = useQuery<Account[]>({
    queryKey: ["/api/accounts"],
  });

  const generateReportMutation = useMutation({
    mutationFn: async (accountId: string) => {
      const response = await apiRequest("POST", "/api/reports/generate", { accountId });
      return response.json() as Promise<SecurityReport>;
    },
    onSuccess: (report) => {
      setGeneratedReports(prev => {
        const filtered = prev.filter(r => r.account.accountId !== report.account.accountId);
        return [...filtered, report];
      });
      toast({
        title: "Report generated successfully!",
        description: `AI security summary created for ${report.account.name}.`,
      });
    },
    onError: (error: any) => {
      toast({
        title: "Failed to generate report",
        description: error.message || "Please check your OpenAI API key and try again.",
        variant: "destructive",
      });
    },
  });

  const handleGenerateReport = (accountId: string) => {
    generateReportMutation.mutate(accountId);
  };

  const getReportForAccount = (accountId: string) => {
    return generatedReports.find(report => report.account.accountId === accountId);
  };

  if (accountsLoading) {
    return (
      <div className="p-8">
        <div className="max-w-7xl mx-auto">
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-6">
            {[...Array(6)].map((_, i) => (
              <Card key={i} className="animate-pulse">
                <CardContent className="p-6">
                  <div className="h-48 bg-gray-200 rounded"></div>
                </CardContent>
              </Card>
            ))}
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="p-8">
      <div className="max-w-7xl mx-auto">
        {/* Report Controls */}
        <Card className="mb-8">
          <CardContent className="p-6">
            <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between space-y-4 lg:space-y-0">
              <div>
                <h2 className="text-xl font-bold text-gray-900">Security Posture Reports</h2>
                <p className="text-gray-600 mt-1">AI-generated insights for your AWS security landscape</p>
              </div>
              <div className="flex items-center space-x-4">
                <Select value={selectedTimeRange} onValueChange={setSelectedTimeRange}>
                  <SelectTrigger className="w-40">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="7">Last 7 Days</SelectItem>
                    <SelectItem value="30">Last 30 Days</SelectItem>
                    <SelectItem value="90">Last 90 Days</SelectItem>
                  </SelectContent>
                </Select>
                <Button className="flex items-center space-x-2">
                  <Download className="h-4 w-4" />
                  <span>Export Report</span>
                </Button>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Account Reports Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-6">
          {accounts?.map((account) => {
            const report = getReportForAccount(account.accountId);
            const isGenerating = generateReportMutation.isPending;
            
            return (
              <Card key={account.id}>
                <CardContent className="p-6">
                  <div className="flex items-center justify-between mb-4">
                    <div>
                      <h3 className="text-lg font-semibold text-gray-900">{account.name}</h3>
                      <p className="text-sm text-gray-500">Account ID: {account.accountId}</p>
                    </div>
                    <div className={`w-12 h-12 ${getRiskScoreBg(account.securityScore)} rounded-full flex items-center justify-center`}>
                      <span className={`text-lg font-bold ${getRiskScoreColor(account.securityScore)}`}>
                        {account.securityScore}
                      </span>
                    </div>
                  </div>

                  {/* AI Summary */}
                  <div className="mb-6">
                    <h4 className="text-sm font-medium text-gray-700 mb-2 flex items-center">
                      <Bot className="h-4 w-4 text-primary mr-2" />
                      AI Summary
                    </h4>
                    {report ? (
                      <p className="text-sm text-gray-600 leading-relaxed">
                        {report.aiSummary}
                      </p>
                    ) : (
                      <p className="text-sm text-gray-400 italic">
                        Generate an AI report to see intelligent insights about this account's security posture.
                      </p>
                    )}
                  </div>

                  {/* Findings Breakdown */}
                  <div className="space-y-3 mb-6">
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-gray-600 flex items-center">
                        <AlertTriangle className="h-4 w-4 text-red-500 mr-1" />
                        Critical Findings
                      </span>
                      <span className="text-sm font-semibold text-red-600">{account.criticalFindings}</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-gray-600 flex items-center">
                        <AlertTriangle className="h-4 w-4 text-orange-500 mr-1" />
                        High Risk Findings
                      </span>
                      <span className="text-sm font-semibold text-orange-600">{account.highFindings}</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-gray-600 flex items-center">
                        <AlertTriangle className="h-4 w-4 text-yellow-500 mr-1" />
                        Medium Risk Findings
                      </span>
                      <span className="text-sm font-semibold text-yellow-600">{account.mediumFindings}</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-gray-600 flex items-center">
                        <CheckCircle className="h-4 w-4 text-green-500 mr-1" />
                        Compliance Score
                      </span>
                      <span className="text-sm font-semibold text-green-600">{account.complianceScore}%</span>
                    </div>
                  </div>

                  {/* Progress Bar */}
                  <div className="mb-4">
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-sm font-medium text-gray-700">Security Score</span>
                      <span className="text-sm font-bold text-gray-900">{account.securityScore}/100</span>
                    </div>
                    <div className="w-full bg-gray-200 rounded-full h-2">
                      <div 
                        className={`h-2 rounded-full ${getProgressColor(account.securityScore)}`}
                        style={{ width: `${account.securityScore}%` }}
                      ></div>
                    </div>
                  </div>

                  {/* Actions */}
                  <div className="flex space-x-2">
                    {report ? (
                      <Button className="flex-1">
                        View Details
                      </Button>
                    ) : (
                      <Button 
                        className="flex-1" 
                        onClick={() => handleGenerateReport(account.accountId)}
                        disabled={isGenerating}
                      >
                        {isGenerating ? "Generating..." : "Generate AI Report"}
                      </Button>
                    )}
                    <Button variant="outline">
                      Get Fixes
                    </Button>
                  </div>
                </CardContent>
              </Card>
            );
          })}
        </div>
      </div>
    </div>
  );
}
