import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { Wrench, CheckCircle, Copy, ExternalLink, Loader2 } from "lucide-react";
import { apiRequest } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { cn } from "@/lib/utils";

interface RemediationStep {
  stepNumber: number;
  title: string;
  description: string;
  commands?: string[];
  consoleSteps?: string[];
}

interface RemediationGuide {
  title: string;
  description: string;
  difficulty: "easy" | "medium" | "hard";
  estimatedTime: string;
  steps: RemediationStep[];
  additionalResources?: Array<{
    title: string;
    url: string;
    type: "documentation" | "video" | "checklist";
  }>;
}

const issueTypes = [
  {
    type: "public-s3-bucket",
    title: "Public S3 Bucket",
    description: "Bucket allows public read access",
  },
  {
    type: "overprivileged-iam-role",
    title: "Overprivileged IAM Role",
    description: "Role has excessive permissions",
  },
  {
    type: "unencrypted-rds",
    title: "Unencrypted RDS",
    description: "Database not encrypted at rest",
  },
  {
    type: "security-group",
    title: "Security Group",
    description: "Overly permissive rules",
  },
];

const difficultyColors = {
  easy: "bg-green-100 text-green-800",
  medium: "bg-yellow-100 text-yellow-800",
  hard: "bg-red-100 text-red-800",
};

export default function Remediation() {
  const [selectedIssue, setSelectedIssue] = useState("public-s3-bucket");
  const [currentStep, setCurrentStep] = useState(1);
  const [completedSteps, setCompletedSteps] = useState<number[]>([]);
  const [remediationGuide, setRemediationGuide] = useState<RemediationGuide | null>(null);
  const { toast } = useToast();

  const getRemediationMutation = useMutation({
    mutationFn: async (issueType: string) => {
      const issueConfig = issueTypes.find(issue => issue.type === issueType);
      const response = await apiRequest("POST", "/api/remediation/steps", { 
        issueType: issueConfig?.title,
        description: issueConfig?.description
      });
      return response.json() as Promise<RemediationGuide>;
    },
    onSuccess: (data) => {
      setRemediationGuide(data);
      setCurrentStep(1);
      setCompletedSteps([]);
    },
    onError: (error: any) => {
      toast({
        title: "Failed to get remediation steps",
        description: error.message || "Please check your OpenAI API key and try again.",
        variant: "destructive",
      });
    },
  });

  const handleIssueSelect = (issueType: string) => {
    setSelectedIssue(issueType);
    getRemediationMutation.mutate(issueType);
  };

  const markStepComplete = (stepNumber: number) => {
    if (!completedSteps.includes(stepNumber)) {
      setCompletedSteps([...completedSteps, stepNumber]);
      if (stepNumber === currentStep && remediationGuide) {
        if (stepNumber < remediationGuide.steps.length) {
          setCurrentStep(stepNumber + 1);
        }
      }
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    toast({
      title: "Copied to clipboard",
      description: "Command copied to your clipboard.",
    });
  };

  const progressPercentage = remediationGuide 
    ? (completedSteps.length / remediationGuide.steps.length) * 100 
    : 0;

  return (
    <div className="p-8">
      <div className="max-w-6xl mx-auto">
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          {/* Issue Selection */}
          <div className="lg:col-span-1">
            <Card className="sticky top-8">
              <CardHeader>
                <CardTitle>Select Security Issue</CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                {issueTypes.map((issue) => (
                  <Button
                    key={issue.type}
                    variant="outline"
                    className={cn(
                      "w-full text-left p-4 h-auto justify-start",
                      selectedIssue === issue.type
                        ? "border-primary bg-blue-50"
                        : "hover:border-primary hover:bg-blue-50"
                    )}
                    onClick={() => handleIssueSelect(issue.type)}
                    disabled={getRemediationMutation.isPending}
                  >
                    <div>
                      <h4 className="font-medium text-gray-900">{issue.title}</h4>
                      <p className="text-sm text-gray-600 mt-1">{issue.description}</p>
                    </div>
                  </Button>
                ))}
              </CardContent>
            </Card>
          </div>

          {/* Remediation Steps */}
          <div className="lg:col-span-2">
            <Card>
              <CardContent className="p-8">
                {getRemediationMutation.isPending ? (
                  <div className="flex items-center justify-center py-12">
                    <Loader2 className="h-8 w-8 animate-spin text-primary mr-3" />
                    <span className="text-gray-600">Generating remediation steps...</span>
                  </div>
                ) : remediationGuide ? (
                  <>
                    <div className="flex items-center justify-between mb-6">
                      <div>
                        <h2 className="text-xl font-bold text-gray-900">{remediationGuide.title}</h2>
                        <p className="text-gray-600 mt-1">{remediationGuide.description}</p>
                      </div>
                      <div className="flex items-center space-x-2">
                        <span className="text-sm text-gray-500">Difficulty:</span>
                        <Badge className={difficultyColors[remediationGuide.difficulty]}>
                          {remediationGuide.difficulty}
                        </Badge>
                      </div>
                    </div>

                    {/* Progress Indicator */}
                    <div className="mb-8">
                      <div className="flex items-center justify-between mb-2">
                        <span className="text-sm font-medium text-gray-700">Progress</span>
                        <span className="text-sm text-gray-500">
                          Step {Math.min(currentStep, remediationGuide.steps.length)} of {remediationGuide.steps.length}
                        </span>
                      </div>
                      <Progress value={progressPercentage} className="h-2" />
                    </div>

                    {/* Remediation Steps */}
                    <div className="space-y-6">
                      {remediationGuide.steps.map((step) => {
                        const isCompleted = completedSteps.includes(step.stepNumber);
                        const isCurrent = step.stepNumber === currentStep;
                        const isUpcoming = step.stepNumber > currentStep;

                        return (
                          <div
                            key={step.stepNumber}
                            className={cn(
                              "border-l-4 pl-6 pr-4 py-4 rounded-r-lg",
                              isCompleted
                                ? "border-green-500 bg-green-50"
                                : isCurrent
                                ? "border-primary bg-blue-50"
                                : "border-gray-300 bg-gray-50"
                            )}
                          >
                            <div className="flex items-start justify-between">
                              <div className="flex-1">
                                <h3 className={cn(
                                  "text-lg font-semibold mb-2",
                                  isCompleted || isCurrent ? "text-gray-900" : "text-gray-500"
                                )}>
                                  <span className={cn(
                                    "inline-flex items-center justify-center w-6 h-6 text-sm font-bold rounded-full mr-3",
                                    isCompleted
                                      ? "bg-green-500 text-white"
                                      : isCurrent
                                      ? "bg-primary text-white"
                                      : "bg-gray-300 text-white"
                                  )}>
                                    {isCompleted ? <CheckCircle className="h-4 w-4" /> : step.stepNumber}
                                  </span>
                                  {step.title}
                                </h3>
                                <p className={cn(
                                  "mb-4",
                                  isCompleted || isCurrent ? "text-gray-700" : "text-gray-500"
                                )}>
                                  {step.description}
                                </p>
                                
                                {(step.commands || step.consoleSteps) && (isCurrent || isCompleted) && (
                                  <div className="space-y-4">
                                    {step.commands && step.commands.length > 0 && (
                                      <div>
                                        <div className="bg-gray-900 text-gray-100 p-4 rounded-lg text-sm font-mono">
                                          <div className="flex items-center justify-between mb-2">
                                            <span className="text-gray-400">AWS CLI Command</span>
                                            <Button
                                              size="sm"
                                              variant="ghost"
                                              className="text-blue-400 hover:text-blue-300 h-auto p-1"
                                              onClick={() => copyToClipboard(step.commands![0])}
                                            >
                                              <Copy className="h-4 w-4" />
                                            </Button>
                                          </div>
                                          <code>{step.commands[0]}</code>
                                        </div>
                                      </div>
                                    )}
                                    
                                    {step.consoleSteps && step.consoleSteps.length > 0 && (
                                      <div>
                                        <h4 className="font-medium text-gray-900 mb-2">Console Steps:</h4>
                                        <ul className="list-disc list-inside space-y-1 text-sm text-gray-700">
                                          {step.consoleSteps.map((consoleStep, index) => (
                                            <li key={index}>{consoleStep}</li>
                                          ))}
                                        </ul>
                                      </div>
                                    )}
                                  </div>
                                )}
                              </div>
                              
                              {isCurrent && !isCompleted && (
                                <Button
                                  className="ml-4"
                                  onClick={() => markStepComplete(step.stepNumber)}
                                >
                                  Mark Complete
                                </Button>
                              )}
                            </div>
                          </div>
                        );
                      })}
                    </div>

                    {/* Additional Resources */}
                    {remediationGuide.additionalResources && remediationGuide.additionalResources.length > 0 && (
                      <div className="mt-8 bg-gray-50 border border-gray-200 rounded-lg p-6">
                        <h4 className="font-semibold text-gray-900 mb-3">Additional Resources</h4>
                        <div className="space-y-2">
                          {remediationGuide.additionalResources.map((resource, index) => (
                            <a
                              key={index}
                              href="#"
                              className="block text-primary hover:text-blue-800 flex items-center"
                            >
                              <span className="mr-2">
                                {resource.type === "documentation" && "📖"}
                                {resource.type === "video" && "🎥"}
                                {resource.type === "checklist" && "📋"}
                              </span>
                              {resource.title}
                              <ExternalLink className="h-3 w-3 ml-1" />
                            </a>
                          ))}
                        </div>
                      </div>
                    )}
                  </>
                ) : (
                  <div className="text-center py-12">
                    <Wrench className="h-12 w-12 text-gray-400 mx-auto mb-4" />
                    <h3 className="text-lg font-medium text-gray-900 mb-2">Select a Security Issue</h3>
                    <p className="text-gray-600">Choose a security issue from the left panel to get step-by-step remediation guidance.</p>
                  </div>
                )}
              </CardContent>
            </Card>
          </div>
        </div>
      </div>
    </div>
  );
}
