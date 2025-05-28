import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";
import { Languages, Lightbulb, Loader2, Sparkles } from "lucide-react";
import { apiRequest } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";

interface PolicyExplanation {
  explanation: string;
}

const examplePolicies = [
  {
    title: "S3 Bucket Policy",
    description: "Prevent public read access to S3 buckets",
    policy: `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::example-bucket/*",
      "Condition": {
        "StringNotEquals": {
          "aws:PrincipalServiceName": "cloudfront.amazonaws.com"
        }
      }
    }
  ]
}`
  },
  {
    title: "IAM Role Policy",
    description: "Restrict EC2 instance access to specific regions",
    policy: `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Action": [
        "ec2:RunInstances",
        "ec2:StartInstances"
      ],
      "Resource": "*",
      "Condition": {
        "StringNotEquals": {
          "aws:RequestedRegion": ["us-east-1", "us-west-2"]
        }
      }
    }
  ]
}`
  }
];

export default function PolicyCopilot() {
  const [policyText, setPolicyText] = useState("");
  const [explanation, setExplanation] = useState<string | null>(null);
  const { toast } = useToast();

  const explainMutation = useMutation({
    mutationFn: async (policy: string) => {
      const response = await apiRequest("POST", "/api/policy-copilot/explain", { policy });
      return response.json() as Promise<PolicyExplanation>;
    },
    onSuccess: (data) => {
      setExplanation(data.explanation);
      toast({
        title: "Policy explained successfully!",
        description: "Your security policy has been translated into plain English.",
      });
    },
    onError: (error: any) => {
      toast({
        title: "Failed to explain policy",
        description: error.message || "Please check your OpenAI API key and try again.",
        variant: "destructive",
      });
    },
  });

  const handleExplainPolicy = () => {
    if (!policyText.trim()) {
      toast({
        title: "Please enter a policy",
        description: "Paste your security policy text to get an explanation.",
        variant: "destructive",
      });
      return;
    }
    
    explainMutation.mutate(policyText);
  };

  const loadExamplePolicy = (policy: string) => {
    setPolicyText(policy);
    setExplanation(null);
  };

  return (
    <div className="p-8">
      <div className="max-w-4xl mx-auto">
        <Card>
          <CardContent className="p-8">
            <div className="text-center mb-8">
              <div className="w-16 h-16 bg-blue-100 rounded-full flex items-center justify-center mx-auto mb-4">
                <Languages className="h-8 w-8 text-primary" />
              </div>
              <h2 className="text-2xl font-bold text-gray-900 mb-2">Security Policy Copilot</h2>
              <p className="text-gray-600">Translate complex security policies into plain English explanations</p>
            </div>

            <div className="space-y-6">
              <div>
                <Label htmlFor="policy-input" className="text-sm font-medium text-gray-700 mb-2 block">
                  Paste your security policy (JSON, IAM Policy, SCP, etc.)
                </Label>
                <Textarea
                  id="policy-input"
                  value={policyText}
                  onChange={(e) => setPolicyText(e.target.value)}
                  className="h-40 resize-none"
                  placeholder={`Paste your policy here, for example:
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Action": ["ec2:*"],
      "Resource": "*"
    }
  ]
}`}
                />
              </div>

              <div className="flex justify-center">
                <Button 
                  onClick={handleExplainPolicy}
                  disabled={explainMutation.isPending}
                  className="px-8 py-3 flex items-center space-x-2"
                >
                  {explainMutation.isPending ? (
                    <Loader2 className="h-4 w-4 animate-spin" />
                  ) : (
                    <Sparkles className="h-4 w-4" />
                  )}
                  <span>{explainMutation.isPending ? "Analyzing..." : "Explain This Policy"}</span>
                </Button>
              </div>

              {explanation && (
                <div className="bg-blue-50 border border-blue-200 rounded-lg p-6">
                  <h3 className="text-lg font-semibold text-gray-900 mb-3 flex items-center">
                    <Lightbulb className="h-5 w-5 text-primary mr-2" />
                    Plain English Explanation
                  </h3>
                  <div 
                    className="prose prose-blue max-w-none text-gray-800"
                    dangerouslySetInnerHTML={{ __html: explanation }}
                  />
                </div>
              )}
            </div>

            {/* Example Policies */}
            <div className="mt-12 border-t border-gray-200 pt-8">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">Try Example Policies</h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {examplePolicies.map((example, index) => (
                  <Button
                    key={index}
                    variant="outline"
                    className="text-left p-4 h-auto justify-start hover:border-primary hover:bg-blue-50"
                    onClick={() => loadExamplePolicy(example.policy)}
                  >
                    <div>
                      <h4 className="font-medium text-gray-900 mb-1">{example.title}</h4>
                      <p className="text-sm text-gray-600">{example.description}</p>
                    </div>
                  </Button>
                ))}
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
