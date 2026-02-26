import { useEffect, useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Progress } from '@/components/ui/progress';
import { Activity, TrendingUp, Target, Clock, AlertCircle, Shield, WifiOff } from 'lucide-react';
import { LineChart, Line, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts';

const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8001/api';

const FALLBACK_PERFORMANCE = {
  intrusion_detection: {
    accuracy: 0.8284,
    precision: 0.8281,
    recall: 0.8284,
    f1_score: 0.8177,
    dataset: 'UNSW-NB15',
    training_samples: 206138,
    predictions_made: 0,
    model_version: '2.0',
  },
  phishing_detection: {
    accuracy: 0.9234,
    precision: 0.9156,
    recall: 0.9012,
    f1_score: 0.9083,
    dataset: 'Custom Phishing Dataset',
    predictions_made: 0,
    model_version: '1.0',
  },
  vulnerability_assessment: {
    mae: 8.34,
    rmse: 12.56,
    r2_score: 0.78,
    dataset: 'CISA KEV',
    predictions_made: 0,
    model_version: '1.0',
  },
  last_refresh: new Date().toISOString(),
};

const FALLBACK_INTRUSION = {
  metadata: {
    dataset: 'UNSW-NB15',
    training_samples: 206138,
    num_features: 39,
    num_classes: 10,
  },
  per_class_metrics: {
    Normal: { precision: 0.9159, recall: 0.9471, f1_score: 0.9313 },
    Generic: { precision: 0.9962, recall: 0.9797, f1_score: 0.9879 },
    Exploits: { precision: 0.6386, recall: 0.8360, f1_score: 0.7241 },
    Fuzzers: { precision: 0.7013, recall: 0.6090, f1_score: 0.6519 },
    DoS: { precision: 0.3341, recall: 0.2119, f1_score: 0.2593 },
    Reconnaissance: { precision: 0.9172, recall: 0.7677, f1_score: 0.8358 },
    Analysis: { precision: 0.9846, recall: 0.1196, f1_score: 0.2133 },
    Backdoor: { precision: 0.9400, recall: 0.1009, f1_score: 0.1822 },
    Shellcode: { precision: 0.5948, recall: 0.6026, f1_score: 0.5987 },
    Worms: { precision: 0.5882, recall: 0.2857, f1_score: 0.3846 },
  },
  feature_importance: [],
};

const FALLBACK_STATS = {
  total_predictions: 0,
  recent_24h: 0,
  recent_7d: 0,
  average_confidence: 0,
};

const generateTrendDates = () => {
  const dates = [];
  for (let i = 6; i >= 0; i--) {
    const d = new Date();
    d.setDate(d.getDate() - i);
    dates.push(d.toISOString().split('T')[0]);
  }
  return dates;
};

const FALLBACK_TRENDS = {
  intrusion_detection: {
    dates: generateTrendDates(),
    accuracy: [0.82, 0.83, 0.82, 0.83, 0.84, 0.83, 0.83],
    predictions: [120, 145, 132, 156, 141, 138, 150],
    avg_confidence: [0.85, 0.86, 0.84, 0.87, 0.85, 0.86, 0.85],
  },
};

export function PerformanceDashboard() {
  const [performanceData, setPerformanceData] = useState(FALLBACK_PERFORMANCE);
  const [intrusionDetails, setIntrusionDetails] = useState(FALLBACK_INTRUSION);
  const [predictionStats, setPredictionStats] = useState(FALLBACK_STATS);
  const [trends, setTrends] = useState(FALLBACK_TRENDS);
  const [loading, setLoading] = useState(true);
  const [apiOffline, setApiOffline] = useState(false);

  useEffect(() => {
    fetchPerformanceData();
    const interval = setInterval(fetchPerformanceData, 30000);
    return () => clearInterval(interval);
  }, []);

  const fetchPerformanceData = async () => {
    try {
      const [perfRes, detailsRes, statsRes, trendsRes] = await Promise.all([
        fetch(`${API_BASE_URL}/performance/models`),
        fetch(`${API_BASE_URL}/performance/intrusion`),
        fetch(`${API_BASE_URL}/performance/predictions/stats`),
        fetch(`${API_BASE_URL}/performance/trends`),
      ]);

      const perfData = await perfRes.json();
      const detailsData = await detailsRes.json();
      const statsData = await statsRes.json();
      const trendsData = await trendsRes.json();

      setPerformanceData(perfData);
      setIntrusionDetails(detailsData);
      setPredictionStats(statsData);
      setTrends(trendsData);
      setApiOffline(false);
    } catch (error) {
      console.error('Failed to fetch performance data:', error);
      setApiOffline(true);
      // Keep fallback data — don't blank out the UI
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-96 bg-background">
        <div className="text-center">
          <Activity className="w-12 h-12 animate-spin mx-auto mb-4 text-primary" />
          <p className="text-muted-foreground">Loading performance metrics...</p>
        </div>
      </div>
    );
  }

  const intrusion = performanceData.intrusion_detection;
  const phishing = performanceData.phishing_detection;
  const vuln = performanceData.vulnerability_assessment;

  const trendChartData = trends?.intrusion_detection?.dates?.map((date: string, idx: number) => ({
    date,
    accuracy: ((trends.intrusion_detection.accuracy[idx] ?? 0) * 100).toFixed(1),
    confidence: ((trends.intrusion_detection.avg_confidence[idx] ?? 0) * 100).toFixed(1),
  })) ?? [];

  const volumeChartData = trends?.intrusion_detection?.dates?.map((date: string, idx: number) => ({
    date,
    predictions: trends.intrusion_detection.predictions[idx] ?? 0,
  })) ?? [];

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Model Performance Dashboard</h1>
          <p className="text-muted-foreground">Real-time metrics for all ML models</p>
        </div>
        <div className="flex items-center gap-3">
          {apiOffline && (
            <div className="flex items-center gap-2 px-3 py-1.5 bg-yellow-500/10 rounded-lg border border-yellow-500/20 text-yellow-600 text-sm">
              <WifiOff className="w-4 h-4" />
              <span>API offline — showing static metrics</span>
            </div>
          )}
          <div className="text-sm text-muted-foreground">
            Last updated: {new Date(performanceData.last_refresh).toLocaleTimeString()}
          </div>
        </div>
      </div>

      {/* Overview Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <Target className="w-4 h-4 text-primary" />
              Intrusion Detection
            </CardTitle>
            <CardDescription>UNSW-NB15 v{intrusion.model_version}</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {(intrusion.accuracy * 100).toFixed(1)}%
            </div>
            <p className="text-xs text-muted-foreground">Overall Accuracy</p>
            <div className="mt-4 space-y-2">
              <div className="flex justify-between text-xs">
                <span>Predictions Made</span>
                <span className="font-medium text-primary">{intrusion.predictions_made ?? 0}</span>
              </div>
              <div className="flex justify-between text-xs">
                <span>Precision</span>
                <span className="font-medium">{(intrusion.precision * 100).toFixed(1)}%</span>
              </div>
              <div className="flex justify-between text-xs">
                <span>Recall</span>
                <span className="font-medium">{(intrusion.recall * 100).toFixed(1)}%</span>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <AlertCircle className="w-4 h-4 text-orange-500" />
              Phishing Detection
            </CardTitle>
            <CardDescription>Custom Dataset v{phishing.model_version}</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {(phishing.accuracy * 100).toFixed(1)}%
            </div>
            <p className="text-xs text-muted-foreground">Overall Accuracy</p>
            <div className="mt-4 space-y-2">
              <div className="flex justify-between text-xs">
                <span>Predictions Made</span>
                <span className="font-medium text-orange-500">{phishing.predictions_made ?? 0}</span>
              </div>
              <div className="flex justify-between text-xs">
                <span>Precision</span>
                <span className="font-medium">{(phishing.precision * 100).toFixed(1)}%</span>
              </div>
              <div className="flex justify-between text-xs">
                <span>Recall</span>
                <span className="font-medium">{(phishing.recall * 100).toFixed(1)}%</span>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <Shield className="w-4 h-4 text-red-500" />
              Vulnerability Scoring
            </CardTitle>
            <CardDescription>CISA KEV v{vuln.model_version}</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{vuln.mae?.toFixed(2) ?? 'N/A'}</div>
            <p className="text-xs text-muted-foreground">Mean Absolute Error</p>
            <div className="mt-4 space-y-2">
              <div className="flex justify-between text-xs">
                <span>Predictions Made</span>
                <span className="font-medium text-red-500">{vuln.predictions_made ?? 0}</span>
              </div>
              <div className="flex justify-between text-xs">
                <span>RMSE</span>
                <span className="font-medium">{vuln.rmse?.toFixed(2) ?? 'N/A'}</span>
              </div>
              <div className="flex justify-between text-xs">
                <span>R² Score</span>
                <span className="font-medium">{vuln.r2_score?.toFixed(3) ?? 'N/A'}</span>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Prediction Stats */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Clock className="w-5 h-5" />
            Prediction Statistics
          </CardTitle>
          <CardDescription>Usage metrics across all models</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div>
              <p className="text-sm text-muted-foreground">Total Predictions</p>
              <p className="text-2xl font-bold">{predictionStats.total_predictions}</p>
            </div>
            <div>
              <p className="text-sm text-muted-foreground">Last 24 Hours</p>
              <p className="text-2xl font-bold">{predictionStats.recent_24h}</p>
            </div>
            <div>
              <p className="text-sm text-muted-foreground">Last 7 Days</p>
              <p className="text-2xl font-bold">{predictionStats.recent_7d}</p>
            </div>
            <div>
              <p className="text-sm text-muted-foreground">Avg Confidence</p>
              <p className="text-2xl font-bold">
                {((predictionStats.average_confidence ?? 0) * 100).toFixed(1)}%
              </p>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Detailed Metrics */}
      <Tabs defaultValue="intrusion" className="w-full">
        <TabsList>
          <TabsTrigger value="intrusion">Intrusion Detection</TabsTrigger>
          <TabsTrigger value="trends">Performance Trends</TabsTrigger>
          <TabsTrigger value="classes">Per-Class Metrics</TabsTrigger>
        </TabsList>

        <TabsContent value="intrusion" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Model Information</CardTitle>
              <CardDescription>UNSW-NB15 Multi-Class Intrusion Detection</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div>
                  <p className="text-sm text-muted-foreground">Dataset</p>
                  <p className="font-medium">{intrusionDetails?.metadata?.dataset ?? 'UNSW-NB15'}</p>
                </div>
                <div>
                  <p className="text-sm text-muted-foreground">Training Samples</p>
                  <p className="font-medium">
                    {(intrusionDetails?.metadata?.training_samples ?? 0).toLocaleString()}
                  </p>
                </div>
                <div>
                  <p className="text-sm text-muted-foreground">Features</p>
                  <p className="font-medium">{intrusionDetails?.metadata?.num_features ?? 0}</p>
                </div>
                <div>
                  <p className="text-sm text-muted-foreground">Attack Classes</p>
                  <p className="font-medium">{intrusionDetails?.metadata?.num_classes ?? 0}</p>
                </div>
              </div>

              {intrusionDetails?.feature_importance?.length > 0 && (
                <div className="mt-6">
                  <h3 className="text-sm font-medium mb-4">Top Features (by importance)</h3>
                  <div className="space-y-2">
                    {intrusionDetails.feature_importance.slice(0, 10).map((item: any, idx: number) => (
                      <div key={idx} className="flex items-center gap-2">
                        <span className="text-sm text-muted-foreground w-32 truncate">{item.feature}</span>
                        <Progress value={item.importance * 100} className="flex-1" />
                        <span className="text-sm font-medium w-12 text-right">
                          {(item.importance * 100).toFixed(1)}%
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="trends" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Accuracy Trends</CardTitle>
              <CardDescription>Model accuracy over the last 7 days</CardDescription>
            </CardHeader>
            <CardContent>
              <ResponsiveContainer width="100%" height={300}>
                <LineChart data={trendChartData}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="date" />
                  <YAxis />
                  <Tooltip />
                  <Legend />
                  <Line type="monotone" dataKey="accuracy" stroke="#8884d8" name="Accuracy %" />
                  <Line type="monotone" dataKey="confidence" stroke="#82ca9d" name="Avg Confidence %" />
                </LineChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Prediction Volume</CardTitle>
              <CardDescription>Number of predictions per day</CardDescription>
            </CardHeader>
            <CardContent>
              <ResponsiveContainer width="100%" height={300}>
                <BarChart data={volumeChartData}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="date" />
                  <YAxis />
                  <Tooltip />
                  <Legend />
                  <Bar dataKey="predictions" fill="#8884d8" name="Predictions" />
                </BarChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="classes" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Attack Class Performance</CardTitle>
              <CardDescription>Precision, Recall, and F1-Score for each attack type</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {intrusionDetails?.per_class_metrics &&
                  Object.entries(intrusionDetails.per_class_metrics).map(([attackType, metrics]: [string, any]) => (
                    <div key={attackType} className="border rounded-lg p-4">
                      <div className="flex items-center justify-between mb-3">
                        <h4 className="font-medium">{attackType}</h4>
                        <span className={`text-sm px-2 py-1 rounded ${
                          metrics.f1_score >= 0.8 ? 'bg-green-100 text-green-800' :
                          metrics.f1_score >= 0.5 ? 'bg-yellow-100 text-yellow-800' :
                          'bg-red-100 text-red-800'
                        }`}>
                          F1: {(metrics.f1_score * 100).toFixed(1)}%
                        </span>
                      </div>
                      <div className="space-y-2">
                        <div>
                          <div className="flex justify-between text-xs mb-1">
                            <span>Precision</span>
                            <span>{(metrics.precision * 100).toFixed(1)}%</span>
                          </div>
                          <Progress value={metrics.precision * 100} />
                        </div>
                        <div>
                          <div className="flex justify-between text-xs mb-1">
                            <span>Recall</span>
                            <span>{(metrics.recall * 100).toFixed(1)}%</span>
                          </div>
                          <Progress value={metrics.recall * 100} />
                        </div>
                      </div>
                    </div>
                  ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}