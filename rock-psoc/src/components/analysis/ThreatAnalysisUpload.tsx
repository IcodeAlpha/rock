import { useState, useCallback } from 'react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { cn } from '@/lib/utils';
import { 
  Upload, 
  FileText, 
  Image, 
  FileCode, 
  AlertCircle, 
  Loader2, 
  CheckCircle,
  X,
  Brain,
  Shield
} from 'lucide-react';
import { ThreatAnalysis, AnalysisFinding, Severity } from '@/types/psoc';
import { toast } from '@/hooks/use-toast';
import { usePredictions } from '@/hooks/usePredictions';

interface ThreatAnalysisUploadProps {
  onAnalysisComplete: (analysis: ThreatAnalysis) => void;
}

const mockAnalyze = (file: File): Promise<ThreatAnalysis> => {
  return new Promise((resolve) => {
    setTimeout(() => {
      const findings: AnalysisFinding[] = [
        {
          id: 'find-1',
          type: 'threat',
          title: 'Suspicious IP Address Detected',
          description: 'Found reference to known malicious IP 192.168.1.100 associated with botnet activity',
          severity: 'high',
          location: 'Line 45',
          confidence: 87,
        },
        {
          id: 'find-2',
          type: 'vulnerability',
          title: 'Potential SQL Injection Pattern',
          description: 'Error message contains database schema information that could be exploited',
          severity: 'critical',
          location: 'Error output section',
          confidence: 92,
        },
        {
          id: 'find-3',
          type: 'suspicious',
          title: 'Unusual Outbound Connection',
          description: 'Connection attempt to non-standard port 4444 detected in network logs',
          severity: 'medium',
          location: 'Network trace',
          confidence: 75,
        },
        {
          id: 'find-4',
          type: 'info',
          title: 'Deprecated Protocol Usage',
          description: 'TLS 1.0 connection detected, recommend upgrading to TLS 1.3',
          severity: 'low',
          confidence: 95,
        },
      ];

      resolve({
        id: `analysis-${Date.now()}`,
        fileName: file.name,
        fileType: file.type.includes('image') ? 'screenshot' : 
                  file.name.endsWith('.log') ? 'log' : 'document',
        uploadedAt: new Date(),
        status: 'completed',
        findings,
        overallSeverity: 'high',
        summary: `Analysis of "${file.name}" revealed ${findings.length} findings. Critical attention required for SQL injection vulnerability and suspicious IP activity. Immediate remediation recommended.`,
        recommendations: [
          'Block identified malicious IP addresses at firewall',
          'Review and sanitize database error handling',
          'Investigate outbound connections on port 4444',
          'Update TLS configuration to use TLS 1.3',
          'Conduct full security audit of affected systems',
        ],
      });
    }, 3000);
  });
};

export function ThreatAnalysisUpload({ onAnalysisComplete }: ThreatAnalysisUploadProps) {
  const [files, setFiles] = useState<File[]>([]);
  const [analyzing, setAnalyzing] = useState(false);
  const [progress, setProgress] = useState(0);
  const [dragActive, setDragActive] = useState(false);
  const { createPrediction } = usePredictions();

  const handleDrag = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === "dragenter" || e.type === "dragover") {
      setDragActive(true);
    } else if (e.type === "dragleave") {
      setDragActive(false);
    }
  }, []);

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    
    const droppedFiles = Array.from(e.dataTransfer.files);
    setFiles(prev => [...prev, ...droppedFiles]);
  }, []);

  const handleFileInput = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files) {
      const selectedFiles = Array.from(e.target.files);
      setFiles(prev => [...prev, ...selectedFiles]);
    }
  };

  const removeFile = (index: number) => {
    setFiles(prev => prev.filter((_, i) => i !== index));
  };

  const getFileIcon = (file: File) => {
    if (file.type.includes('image')) return <Image className="w-5 h-5 text-primary" />;
    if (file.name.endsWith('.log') || file.name.endsWith('.txt')) return <FileCode className="w-5 h-5 text-warning" />;
    return <FileText className="w-5 h-5 text-muted-foreground" />;
  };

  const startAnalysis = async () => {
    if (files.length === 0) return;
    
    setAnalyzing(true);
    setProgress(0);
    
    const progressInterval = setInterval(() => {
      setProgress(prev => Math.min(prev + Math.random() * 15, 90));
    }, 500);

    try {
      for (const file of files) {
        const analysis = await mockAnalyze(file);
        
        // Save analysis as a prediction to the database
        const highestSeverityFinding = analysis.findings.reduce((highest, finding) => {
          const severityOrder = { critical: 4, high: 3, medium: 2, low: 1 };
          return severityOrder[finding.severity] > severityOrder[highest.severity] ? finding : highest;
        }, analysis.findings[0]);

        await createPrediction.mutateAsync({
          title: `File Analysis: ${analysis.fileName}`,
          description: analysis.summary,
          severity: analysis.overallSeverity,
          probability: Math.round(Math.random() * 30 + 60), // 60-90%
          confidence: highestSeverityFinding?.confidence || 75,
          impact: analysis.overallSeverity === 'critical' ? 'critical' : 
                  analysis.overallSeverity === 'high' ? 'high' : 'medium',
          timeframe: 'Immediate',
          affected_systems: analysis.findings
            .filter(f => f.location)
            .map(f => f.location || 'Unknown'),
          source: 'File Analysis',
        });
        
        onAnalysisComplete(analysis);
      }
      
      setProgress(100);
      toast({
        title: "Analysis Complete",
        description: `Successfully analyzed ${files.length} file(s) and saved as predictions.`,
      });
      setFiles([]);
    } catch (error) {
      toast({
        title: "Analysis Failed",
        description: "An error occurred during analysis. Please try again.",
        variant: "destructive",
      });
    } finally {
      clearInterval(progressInterval);
      setAnalyzing(false);
      setProgress(0);
    }
  };

  return (
    <div className="rounded-xl border border-border bg-card/50 backdrop-blur-sm overflow-hidden">
      <div className="p-4 border-b border-border flex items-center gap-3">
        <div className="w-10 h-10 rounded-lg bg-primary/20 flex items-center justify-center">
          <Brain className="w-5 h-5 text-primary" />
        </div>
        <div>
          <h3 className="font-semibold">AI Threat Analysis</h3>
          <p className="text-xs text-muted-foreground">Upload files for automated security analysis</p>
        </div>
      </div>

      <div className="p-4 space-y-4">
        {/* Drop Zone */}
        <div
          className={cn(
            "border-2 border-dashed rounded-lg p-8 text-center transition-all",
            dragActive 
              ? "border-primary bg-primary/10" 
              : "border-border hover:border-primary/50 hover:bg-secondary/20",
            analyzing && "pointer-events-none opacity-50"
          )}
          onDragEnter={handleDrag}
          onDragLeave={handleDrag}
          onDragOver={handleDrag}
          onDrop={handleDrop}
        >
          <input
            type="file"
            multiple
            accept=".txt,.log,.pdf,.png,.jpg,.jpeg,.doc,.docx,.json,.csv"
            onChange={handleFileInput}
            className="hidden"
            id="file-upload"
            disabled={analyzing}
          />
          <label htmlFor="file-upload" className="cursor-pointer">
            <Upload className="w-10 h-10 mx-auto mb-3 text-muted-foreground" />
            <p className="font-medium mb-1">Drop files here or click to upload</p>
            <p className="text-xs text-muted-foreground">
              Supports: Error logs, screenshots, documents, threat reports
            </p>
            <p className="text-xs text-muted-foreground mt-1">
              TXT, LOG, PDF, PNG, JPG, DOC, JSON, CSV
            </p>
          </label>
        </div>

        {/* File List */}
        {files.length > 0 && (
          <div className="space-y-2">
            <p className="text-sm font-medium">Files to analyze ({files.length})</p>
            {files.map((file, index) => (
              <div 
                key={index}
                className="flex items-center gap-3 p-3 rounded-lg bg-secondary/30 border border-border"
              >
                {getFileIcon(file)}
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium truncate">{file.name}</p>
                  <p className="text-xs text-muted-foreground">
                    {(file.size / 1024).toFixed(1)} KB
                  </p>
                </div>
                <Button
                  variant="ghost"
                  size="icon"
                  onClick={() => removeFile(index)}
                  disabled={analyzing}
                >
                  <X className="w-4 h-4" />
                </Button>
              </div>
            ))}
          </div>
        )}

        {/* Progress Bar */}
        {analyzing && (
          <div className="space-y-2">
            <div className="flex items-center justify-between text-sm">
              <span className="flex items-center gap-2">
                <Loader2 className="w-4 h-4 animate-spin" />
                Analyzing threats...
              </span>
              <span>{Math.round(progress)}%</span>
            </div>
            <div className="h-2 bg-secondary rounded-full overflow-hidden">
              <div 
                className="h-full bg-gradient-to-r from-primary to-cyan-400 transition-all duration-300"
                style={{ width: `${progress}%` }}
              />
            </div>
            <div className="text-xs text-muted-foreground space-y-1">
              <p>• Scanning for malware signatures...</p>
              <p>• Correlating with OSINT databases...</p>
              <p>• Identifying vulnerabilities...</p>
            </div>
          </div>
        )}

        {/* Analyze Button */}
        <Button
          onClick={startAnalysis}
          disabled={files.length === 0 || analyzing}
          className="w-full"
          variant="cyber"
        >
          {analyzing ? (
            <>
              <Loader2 className="w-4 h-4 mr-2 animate-spin" />
              Analyzing...
            </>
          ) : (
            <>
              <Shield className="w-4 h-4 mr-2" />
              Analyze {files.length > 0 ? `${files.length} File(s)` : 'Files'}
            </>
          )}
        </Button>
      </div>
    </div>
  );
}
