import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { BookOpen, Sparkles, Clock, User, Edit, AlertTriangle, CheckCircle, Loader2 } from "lucide-react";
import { apiRequest } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import type { Playbook } from "@shared/schema";

const playbookTypes = [
  { value: "new-account", label: "New Account Setup" },
  { value: "incident-response", label: "Security Incident Response" },
  { value: "compliance-audit", label: "Compliance Audit Preparation" },
  { value: "data-breach", label: "Data Breach Response" },
  { value: "access-review", label: "Quarterly Access Review" },
];

const difficultyColors = {
  easy: "bg-green-100 text-green-800",
  medium: "bg-yellow-100 text-yellow-800",
  hard: "bg-red-100 text-red-800",
};

const statusColors = {
  ready: "bg-green-100 text-green-800",
  draft: "bg-yellow-100 text-yellow-800",
};

const getPlaybookIcon = (type: string) => {
  switch (type) {
    case "new-account":
      return <BookOpen className="h-5 w-5 text-orange-600" />;
    case "incident-response":
      return <AlertTriangle className="h-5 w-5 text-red-600" />;
    case "compliance-audit":
      return <CheckCircle className="h-5 w-5 text-primary" />;
    default:
      return <BookOpen className="h-5 w-5 text-orange-600" />;
  }
};

export default function Playbooks() {
  const [selectedType, setSelectedType] = useState("");
  const [requirements, setRequirements] = useState("");
  const queryClient = useQueryClient();
  const { toast } = useToast();

  const { data: playbooks = [], isLoading } = useQuery<Playbook[]>({
    queryKey: ["/api/playbooks"],
  });

  const generatePlaybookMutation = useMutation({
    mutationFn: async ({ type, requirements }: { type: string; requirements: string }) => {
      const response = await apiRequest("POST", "/api/playbooks/generate", { type, requirements });
      return response.json() as Promise<Playbook>;
    },
    onSuccess: (newPlaybook) => {
      queryClient.invalidateQueries({ queryKey: ["/api/playbooks"] });
      setSelectedType("");
      setRequirements("");
      toast({
        title: "Playbook generated successfully!",
        description: `${newPlaybook.title} has been created and is ready to use.`,
      });
    },
    onError: (error: any) => {
      toast({
        title: "Failed to generate playbook",
        description: error.message || "Please check your OpenAI API key and try again.",
        variant: "destructive",
      });
    },
  });

  const handleGeneratePlaybook = () => {
    if (!selectedType) {
      toast({
        title: "Please select a playbook type",
        description: "Choose what type of playbook you need from the dropdown.",
        variant: "destructive",
      });
      return;
    }

    generatePlaybookMutation.mutate({ type: selectedType, requirements });
  };

  if (isLoading) {
    return (
      <div className="p-8">
        <div className="max-w-6xl mx-auto">
          <Card className="mb-8 animate-pulse">
            <CardContent className="p-8">
              <div className="h-32 bg-gray-200 rounded"></div>
            </CardContent>
          </Card>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
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
      <div className="max-w-6xl mx-auto">
        {/* Playbook Generator */}
        <Card className="mb-8">
          <CardContent className="p-8">
            <div className="text-center mb-8">
              <div className="w-16 h-16 bg-orange-100 rounded-full flex items-center justify-center mx-auto mb-4">
                <BookOpen className="h-8 w-8 text-orange-600" />
              </div>
              <h2 className="text-2xl font-bold text-gray-900 mb-2">Automated Playbook Generator</h2>
              <p className="text-gray-600">Generate step-by-step security playbooks customized for your organization</p>
            </div>

            <div className="max-w-2xl mx-auto">
              <div className="space-y-6">
                <div>
                  <Label htmlFor="playbook-type" className="text-sm font-medium text-gray-700 mb-2 block">
                    What type of playbook do you need?
                  </Label>
                  <Select value={selectedType} onValueChange={setSelectedType}>
                    <SelectTrigger id="playbook-type">
                      <SelectValue placeholder="Select a playbook type..." />
                    </SelectTrigger>
                    <SelectContent>
                      {playbookTypes.map((type) => (
                        <SelectItem key={type.value} value={type.value}>
                          {type.label}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>

                <div>
                  <Label htmlFor="requirements" className="text-sm font-medium text-gray-700 mb-2 block">
                    Specific requirements (optional)
                  </Label>
                  <Textarea
                    id="requirements"
                    value={requirements}
                    onChange={(e) => setRequirements(e.target.value)}
                    className="h-24 resize-none"
                    placeholder="Describe any specific requirements, constraints, or customizations needed..."
                  />
                </div>

                <div className="flex justify-center">
                  <Button 
                    onClick={handleGeneratePlaybook}
                    disabled={generatePlaybookMutation.isPending}
                    className="px-8 py-3 bg-orange-600 hover:bg-orange-700 flex items-center space-x-2"
                  >
                    {generatePlaybookMutation.isPending ? (
                      <Loader2 className="h-4 w-4 animate-spin" />
                    ) : (
                      <Sparkles className="h-4 w-4" />
                    )}
                    <span>{generatePlaybookMutation.isPending ? "Generating..." : "Generate Playbook"}</span>
                  </Button>
                </div>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Existing Playbooks */}
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <CardTitle>Saved Playbooks</CardTitle>
              <Button variant="ghost" className="text-orange-600">View All</Button>
            </div>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
              {playbooks.map((playbook) => (
                <Card key={playbook.id} className="border border-gray-200 hover:border-primary hover:shadow-md transition-all">
                  <CardContent className="p-6">
                    <div className="flex items-start justify-between mb-4">
                      <div className="w-10 h-10 bg-orange-100 rounded-lg flex items-center justify-center">
                        {getPlaybookIcon(playbook.type)}
                      </div>
                      <Badge className={statusColors[playbook.status as keyof typeof statusColors]}>
                        {playbook.status}
                      </Badge>
                    </div>
                    
                    <h4 className="text-lg font-semibold text-gray-900 mb-2">{playbook.title}</h4>
                    <p className="text-gray-600 text-sm mb-4">{playbook.description}</p>
                    
                    <div className="flex items-center justify-between text-sm text-gray-500 mb-4">
                      <span className="flex items-center">
                        <User className="h-4 w-4 mr-1" />
                        {Array.isArray(playbook.steps) ? playbook.steps.length : 0} steps
                      </span>
                      <span className="flex items-center">
                        <Clock className="h-4 w-4 mr-1" />
                        ~{playbook.estimatedTime || 0} min
                      </span>
                    </div>
                    
                    <div className="mb-4">
                      <Badge className={difficultyColors[playbook.difficulty as keyof typeof difficultyColors]}>
                        {playbook.difficulty}
                      </Badge>
                    </div>
                    
                    <div className="flex space-x-2">
                      <Button 
                        className="flex-1" 
                        disabled={playbook.status === "draft"}
                      >
                        {playbook.status === "ready" ? "Use Playbook" : "In Progress"}
                      </Button>
                      <Button variant="outline" size="icon">
                        <Edit className="h-4 w-4" />
                      </Button>
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
            
            {playbooks.length === 0 && (
              <div className="text-center py-12">
                <BookOpen className="h-12 w-12 text-gray-400 mx-auto mb-4" />
                <h3 className="text-lg font-medium text-gray-900 mb-2">No playbooks yet</h3>
                <p className="text-gray-600">Generate your first security playbook using the form above.</p>
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
