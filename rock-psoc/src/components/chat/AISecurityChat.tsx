import { useState, useRef, useEffect } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Card } from '@/components/ui/card';
import { Brain, Send, Loader2, Sparkles, User, AlertCircle } from 'lucide-react';
import { cn } from '@/lib/utils';
import { toast } from 'sonner';
import ReactMarkdown from 'react-markdown';

interface Message {
  role: 'user' | 'assistant';
  content: string;
  timestamp: Date;
}

interface AISecurityChatProps {
  threatId?: string; // Optional: if explaining a specific threat
}

const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8001/api';

export function AISecurityChat({ threatId }: AISecurityChatProps) {
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [isGeneratingBriefing, setIsGeneratingBriefing] = useState(false);
  const scrollRef = useRef<HTMLDivElement>(null);

  // Auto-scroll to bottom when new messages arrive
  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [messages]);

  // If threatId provided, auto-request explanation
  useEffect(() => {
    if (threatId) {
      handleExplainThreat(threatId);
    }
  }, [threatId]);

  const sendMessage = async () => {
    if (!input.trim() || isLoading) return;

    const userMessage: Message = {
      role: 'user',
      content: input,
      timestamp: new Date(),
    };

    setMessages(prev => [...prev, userMessage]);
    setInput('');
    setIsLoading(true);

    try {
      const response = await fetch(`${API_BASE_URL}/chat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          message: input,
          conversation_history: messages.map(m => ({
            role: m.role,
            content: m.content
          })),
          include_context: true,
        }),
      });

      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.detail || 'Failed to get AI response');
      }

      const data = await response.json();

      const assistantMessage: Message = {
        role: 'assistant',
        content: data.response,
        timestamp: new Date(),
      };

      setMessages(prev => [...prev, assistantMessage]);

    } catch (error) {
      console.error('Chat error:', error);
      toast.error(error instanceof Error ? error.message : 'Failed to send message');

      setMessages(prev => [...prev, {
        role: 'assistant',
        content: '❌ Sorry, I encountered an error. Please make sure the AI service is configured properly (GEMINI_API_KEY set in backend .env file).',
        timestamp: new Date(),
      }]);
    } finally {
      setIsLoading(false);
    }
  };

  const handleExplainThreat = async (id: string) => {
    setIsLoading(true);

    try {
      const response = await fetch(`${API_BASE_URL}/chat/explain/${id}`, {
        method: 'POST',
      });

      if (!response.ok) {
        throw new Error('Failed to get threat explanation');
      }

      const data = await response.json();

      const assistantMessage: Message = {
        role: 'assistant',
        content: `**Explanation for: ${data.threat_title}**\n\n${data.explanation}`,
        timestamp: new Date(),
      };

      setMessages([assistantMessage]);

    } catch (error) {
      console.error('Explanation error:', error);
      toast.error('Failed to get threat explanation');
    } finally {
      setIsLoading(false);
    }
  };

  const generateBriefing = async (period: 'daily' | 'weekly') => {
    setIsGeneratingBriefing(true);

    try {
      const response = await fetch(`${API_BASE_URL}/chat/briefing?period=${period}`, {
        method: 'POST',
      });

      if (!response.ok) {
        throw new Error('Failed to generate briefing');
      }

      const data = await response.json();

      const briefingMessage: Message = {
        role: 'assistant',
        content: `**${period.charAt(0).toUpperCase() + period.slice(1)} Security Briefing**\n\n${data.briefing}`,
        timestamp: new Date(),
      };

      setMessages(prev => [...prev, briefingMessage]);
      toast.success(`${period.charAt(0).toUpperCase() + period.slice(1)} briefing generated`);

    } catch (error) {
      console.error('Briefing error:', error);
      toast.error('Failed to generate briefing');
    } finally {
      setIsGeneratingBriefing(false);
    }
  };

  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      sendMessage();
    }
  };

  const suggestedQuestions = [
    "What's the most dangerous vulnerability right now?",
    "Why are we seeing so many phishing alerts?",
    "Summarize today's security posture",
    "Show me all critical threats from last week",
    "What patterns do you see in recent attacks?",
  ];

  return (
    <Card className="flex flex-col h-[600px] border-primary/30">
      {/* Header */}
      <div className="p-4 border-b border-border flex items-center justify-between bg-gradient-to-r from-primary/5 to-transparent">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-primary/20 flex items-center justify-center">
            <Brain className="w-6 h-6 text-primary" />
          </div>
          <div>
            <h3 className="font-semibold">AI Security Analyst</h3>
            <p className="text-xs text-muted-foreground">
              Ask questions about your security posture
            </p>
          </div>
        </div>

        <div className="flex gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={() => generateBriefing('daily')}
            disabled={isGeneratingBriefing}
          >
            {isGeneratingBriefing ? (
              <Loader2 className="w-4 h-4 animate-spin" />
            ) : (
              <>
                <Sparkles className="w-4 h-4 mr-1" />
                Daily Brief
              </>
            )}
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={() => generateBriefing('weekly')}
            disabled={isGeneratingBriefing}
          >
            Weekly Brief
          </Button>
        </div>
      </div>

      {/* Messages */}
      <ScrollArea className="flex-1 p-4">
        {messages.length === 0 ? (
          <div className="h-full flex flex-col items-center justify-center text-center">
            <Brain className="w-16 h-16 text-muted-foreground mb-4 opacity-20" />
            <h4 className="font-medium mb-2">Start a conversation</h4>
            <p className="text-sm text-muted-foreground mb-6">
              Ask me anything about your security threats and vulnerabilities
            </p>

            {/* Suggested Questions */}
            <div className="space-y-2 w-full max-w-md">
              <p className="text-xs text-muted-foreground mb-3">Try asking:</p>
              {suggestedQuestions.map((question, idx) => (
                <button
                  key={idx}
                  onClick={() => setInput(question)}
                  className="w-full p-3 text-left text-sm rounded-lg border border-border hover:bg-secondary transition-colors"
                >
                  "{question}"
                </button>
              ))}
            </div>
          </div>
        ) : (
          <div className="space-y-4">
            {messages.map((message, idx) => (
              <div
                key={idx}
                className={cn(
                  'flex gap-3',
                  message.role === 'user' ? 'justify-end' : 'justify-start'
                )}
              >
                {message.role === 'assistant' && (
                  <div className="w-8 h-8 rounded-full bg-primary/20 flex items-center justify-center flex-shrink-0">
                    <Brain className="w-4 h-4 text-primary" />
                  </div>
                )}

                <div
                  className={cn(
                    'max-w-[80%] rounded-lg p-3',
                    message.role === 'user'
                      ? 'bg-primary text-primary-foreground'
                      : 'bg-secondary'
                  )}
                >
                  {message.role === 'assistant' ? (
                    <div className="text-sm prose prose-sm dark:prose-invert max-w-none
                      prose-headings:text-foreground
                      prose-p:text-foreground
                      prose-strong:text-foreground
                      prose-ul:text-foreground
                      prose-ol:text-foreground
                      prose-li:text-foreground
                    ">
                      <ReactMarkdown>{message.content}</ReactMarkdown>
                    </div>
                  ) : (
                    <div className="text-sm whitespace-pre-wrap">{message.content}</div>
                  )}
                  <div className="text-xs mt-2 opacity-50">
                    {message.timestamp.toLocaleTimeString()}
                  </div>
                </div>

                {message.role === 'user' && (
                  <div className="w-8 h-8 rounded-full bg-muted flex items-center justify-center flex-shrink-0">
                    <User className="w-4 h-4" />
                  </div>
                )}
              </div>
            ))}
            <div ref={scrollRef} />
          </div>
        )}
      </ScrollArea>

      {/* Input */}
      <div className="p-4 border-t border-border">
        <div className="flex gap-2">
          <Input
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyPress={handleKeyPress}
            placeholder="Ask about threats, vulnerabilities, or security posture..."
            disabled={isLoading}
            className="flex-1"
          />
          <Button
            onClick={sendMessage}
            disabled={isLoading || !input.trim()}
            size="icon"
          >
            {isLoading ? (
              <Loader2 className="w-4 h-4 animate-spin" />
            ) : (
              <Send className="w-4 h-4" />
            )}
          </Button>
        </div>

        {isLoading && (
          <div className="flex items-center gap-2 mt-2 text-xs text-muted-foreground">
            <Loader2 className="w-3 h-3 animate-spin" />
            AI is analyzing your security data...
          </div>
        )}
      </div>
    </Card>
  );
}