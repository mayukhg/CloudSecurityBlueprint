import { useState, useEffect, useRef } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Bot, User, Send, Circle } from "lucide-react";
import { apiRequest } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import type { ChatMessage } from "@shared/schema";

const quickQuestions = [
  "Show my security score",
  "What are my critical findings?",
  "Explain this IAM policy",
  "Is my account compliant with encryption policy?",
  "How do I fix a public S3 bucket?",
];

export default function Chat() {
  const [sessionId] = useState(() => `session-${Date.now()}`);
  const [inputMessage, setInputMessage] = useState("");
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const queryClient = useQueryClient();
  const { toast } = useToast();

  const { data: messages = [], isLoading } = useQuery<ChatMessage[]>({
    queryKey: ["/api/chat/messages", sessionId],
  });

  const sendMessageMutation = useMutation({
    mutationFn: async (message: string) => {
      const response = await apiRequest("POST", "/api/chat/message", {
        sessionId,
        message,
        isUser: 1,
      });
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/chat/messages", sessionId] });
      setInputMessage("");
    },
    onError: (error: any) => {
      toast({
        title: "Failed to send message",
        description: error.message || "Please check your OpenAI API key and try again.",
        variant: "destructive",
      });
    },
  });

  const handleSendMessage = () => {
    if (!inputMessage.trim()) return;
    sendMessageMutation.mutate(inputMessage);
  };

  const handleQuickQuestion = (question: string) => {
    sendMessageMutation.mutate(question);
  };

  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      handleSendMessage();
    }
  };

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  // Add welcome message if no messages exist
  const allMessages = messages.length === 0 ? [
    {
      id: 0,
      sessionId,
      message: "Hello! I'm your Security Concierge. I can help you with security questions about your AWS accounts, explain policies, provide remediation guidance, and more. What would you like to know?",
      isUser: 0,
      timestamp: new Date(),
    }
  ] : messages;

  return (
    <div className="p-8">
      <div className="max-w-4xl mx-auto">
        <Card className="h-[600px] flex flex-col">
          {/* Chat Header */}
          <CardHeader className="border-b border-gray-200">
            <div className="flex items-center space-x-3">
              <div className="w-10 h-10 bg-primary rounded-full flex items-center justify-center">
                <Bot className="h-5 w-5 text-white" />
              </div>
              <div>
                <h2 className="text-lg font-semibold text-gray-900">Security Concierge</h2>
                <p className="text-sm text-gray-600">Ask me anything about your AWS security</p>
              </div>
              <div className="ml-auto">
                <Badge className="bg-green-100 text-green-800 hover:bg-green-100">
                  <Circle className="w-2 h-2 fill-current mr-2" />
                  Online
                </Badge>
              </div>
            </div>
          </CardHeader>

          {/* Chat Messages */}
          <CardContent className="flex-1 p-6 overflow-y-auto space-y-4">
            {isLoading ? (
              <div className="flex justify-center py-8">
                <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
              </div>
            ) : (
              allMessages.map((message) => (
                <div
                  key={message.id}
                  className={`flex items-start space-x-3 ${message.isUser ? 'justify-end' : ''}`}
                >
                  {!message.isUser && (
                    <div className="w-8 h-8 bg-primary rounded-full flex items-center justify-center flex-shrink-0">
                      <Bot className="h-4 w-4 text-white" />
                    </div>
                  )}
                  <div className={`rounded-lg p-4 max-w-md ${
                    message.isUser 
                      ? 'bg-primary text-white' 
                      : 'bg-blue-50 text-gray-800'
                  }`}>
                    <p className="whitespace-pre-wrap">{message.message}</p>
                  </div>
                  {message.isUser && (
                    <div className="w-8 h-8 bg-gray-300 rounded-full flex items-center justify-center flex-shrink-0">
                      <User className="h-4 w-4 text-gray-600" />
                    </div>
                  )}
                </div>
              ))
            )}
            {sendMessageMutation.isPending && (
              <div className="flex items-start space-x-3">
                <div className="w-8 h-8 bg-primary rounded-full flex items-center justify-center flex-shrink-0">
                  <Bot className="h-4 w-4 text-white" />
                </div>
                <div className="bg-blue-50 rounded-lg p-4 max-w-md">
                  <div className="flex space-x-1">
                    <div className="w-2 h-2 bg-gray-400 rounded-full animate-bounce"></div>
                    <div className="w-2 h-2 bg-gray-400 rounded-full animate-bounce" style={{ animationDelay: '0.1s' }}></div>
                    <div className="w-2 h-2 bg-gray-400 rounded-full animate-bounce" style={{ animationDelay: '0.2s' }}></div>
                  </div>
                </div>
              </div>
            )}
            <div ref={messagesEndRef} />
          </CardContent>

          {/* Chat Input */}
          <div className="p-6 border-t border-gray-200">
            <div className="flex items-center space-x-4">
              <Input
                value={inputMessage}
                onChange={(e) => setInputMessage(e.target.value)}
                onKeyPress={handleKeyPress}
                placeholder="Ask about security policies, compliance, remediation steps..."
                className="flex-1"
                disabled={sendMessageMutation.isPending}
              />
              <Button 
                onClick={handleSendMessage}
                disabled={!inputMessage.trim() || sendMessageMutation.isPending}
                className="flex items-center space-x-2"
              >
                <span>Send</span>
                <Send className="h-4 w-4" />
              </Button>
            </div>
            
            {/* Quick Actions */}
            <div className="mt-4 flex flex-wrap gap-2">
              {quickQuestions.map((question) => (
                <Button
                  key={question}
                  variant="secondary"
                  size="sm"
                  className="text-xs"
                  onClick={() => handleQuickQuestion(question)}
                  disabled={sendMessageMutation.isPending}
                >
                  {question}
                </Button>
              ))}
            </div>
          </div>
        </Card>
      </div>
    </div>
  );
}
