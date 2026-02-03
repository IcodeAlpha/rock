import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';

const data = [
  { name: 'Mon', predictions: 4, incidents: 2, alerts: 8 },
  { name: 'Tue', predictions: 3, incidents: 1, alerts: 5 },
  { name: 'Wed', predictions: 5, incidents: 3, alerts: 12 },
  { name: 'Thu', predictions: 2, incidents: 1, alerts: 6 },
  { name: 'Fri', predictions: 6, incidents: 4, alerts: 15 },
  { name: 'Sat', predictions: 3, incidents: 2, alerts: 7 },
  { name: 'Sun', predictions: 4, incidents: 2, alerts: 9 },
];

export function ThreatChart() {
  return (
    <div className="p-6 rounded-xl border border-border bg-card/50 backdrop-blur-sm">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h3 className="font-semibold text-lg">Threat Activity Timeline</h3>
          <p className="text-sm text-muted-foreground">Last 7 days overview</p>
        </div>
        <div className="flex items-center gap-4 text-xs">
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 rounded-full bg-primary" />
            <span className="text-muted-foreground">Predictions</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 rounded-full bg-destructive" />
            <span className="text-muted-foreground">Incidents</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 rounded-full bg-warning" />
            <span className="text-muted-foreground">Alerts</span>
          </div>
        </div>
      </div>
      <div className="h-64">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={data} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
            <defs>
              <linearGradient id="colorPredictions" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="hsl(187, 100%, 50%)" stopOpacity={0.4}/>
                <stop offset="95%" stopColor="hsl(187, 100%, 50%)" stopOpacity={0}/>
              </linearGradient>
              <linearGradient id="colorIncidents" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="hsl(0, 84%, 60%)" stopOpacity={0.4}/>
                <stop offset="95%" stopColor="hsl(0, 84%, 60%)" stopOpacity={0}/>
              </linearGradient>
              <linearGradient id="colorAlerts" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="hsl(38, 92%, 50%)" stopOpacity={0.4}/>
                <stop offset="95%" stopColor="hsl(38, 92%, 50%)" stopOpacity={0}/>
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="hsl(222, 47%, 18%)" />
            <XAxis 
              dataKey="name" 
              stroke="hsl(215, 20%, 55%)" 
              fontSize={12}
              tickLine={false}
              axisLine={false}
            />
            <YAxis 
              stroke="hsl(215, 20%, 55%)" 
              fontSize={12}
              tickLine={false}
              axisLine={false}
            />
            <Tooltip 
              contentStyle={{ 
                backgroundColor: 'hsl(222, 47%, 8%)', 
                border: '1px solid hsl(222, 47%, 18%)',
                borderRadius: '8px',
                boxShadow: '0 4px 20px rgba(0,0,0,0.3)'
              }}
              labelStyle={{ color: 'hsl(210, 40%, 98%)' }}
            />
            <Area 
              type="monotone" 
              dataKey="alerts" 
              stroke="hsl(38, 92%, 50%)" 
              strokeWidth={2}
              fillOpacity={1} 
              fill="url(#colorAlerts)" 
            />
            <Area 
              type="monotone" 
              dataKey="predictions" 
              stroke="hsl(187, 100%, 50%)" 
              strokeWidth={2}
              fillOpacity={1} 
              fill="url(#colorPredictions)" 
            />
            <Area 
              type="monotone" 
              dataKey="incidents" 
              stroke="hsl(0, 84%, 60%)" 
              strokeWidth={2}
              fillOpacity={1} 
              fill="url(#colorIncidents)" 
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
