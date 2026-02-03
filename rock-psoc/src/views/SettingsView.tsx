import { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Switch } from '@/components/ui/switch';
import { 
  Settings, 
  Bell, 
  Shield, 
  Users, 
  Database,
  Key,
  Globe,
  Palette,
  Save
} from 'lucide-react';
import { toast } from '@/hooks/use-toast';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';

export function SettingsView() {
  const [notifications, setNotifications] = useState({
    criticalAlerts: true,
    highAlerts: true,
    mediumAlerts: false,
    lowAlerts: false,
    emailDigest: true,
    browserNotifications: true,
  });

  const [security, setSecurity] = useState({
    twoFactor: true,
    sessionTimeout: '30',
    ipWhitelist: false,
  });

  const handleSave = () => {
    toast({
      title: "Settings Saved",
      description: "Your preferences have been updated successfully.",
    });
  };

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Settings className="w-7 h-7 text-primary" />
            Settings
          </h1>
          <p className="text-muted-foreground mt-1">
            Configure your PSOC preferences
          </p>
        </div>
        <Button variant="cyber" onClick={handleSave}>
          <Save className="w-4 h-4 mr-2" />
          Save Changes
        </Button>
      </div>

      <Tabs defaultValue="notifications" className="w-full">
        <TabsList className="grid w-full max-w-2xl grid-cols-4">
          <TabsTrigger value="notifications" className="flex items-center gap-2">
            <Bell className="w-4 h-4" />
            Notifications
          </TabsTrigger>
          <TabsTrigger value="security" className="flex items-center gap-2">
            <Shield className="w-4 h-4" />
            Security
          </TabsTrigger>
          <TabsTrigger value="integrations" className="flex items-center gap-2">
            <Globe className="w-4 h-4" />
            Integrations
          </TabsTrigger>
          <TabsTrigger value="appearance" className="flex items-center gap-2">
            <Palette className="w-4 h-4" />
            Appearance
          </TabsTrigger>
        </TabsList>

        <TabsContent value="notifications" className="mt-6">
          <div className="max-w-2xl space-y-6">
            <div className="p-4 rounded-lg border border-border bg-card/50">
              <h3 className="font-medium mb-4">Alert Notifications</h3>
              <div className="space-y-4">
                {[
                  { key: 'criticalAlerts', label: 'Critical Alerts', desc: 'Immediate notification for critical threats' },
                  { key: 'highAlerts', label: 'High Alerts', desc: 'Notifications for high-severity events' },
                  { key: 'mediumAlerts', label: 'Medium Alerts', desc: 'Notifications for medium-severity events' },
                  { key: 'lowAlerts', label: 'Low Alerts', desc: 'Notifications for low-severity events' },
                ].map((item) => (
                  <div key={item.key} className="flex items-center justify-between">
                    <div>
                      <p className="font-medium text-sm">{item.label}</p>
                      <p className="text-xs text-muted-foreground">{item.desc}</p>
                    </div>
                    <Switch 
                      checked={notifications[item.key as keyof typeof notifications]}
                      onCheckedChange={(checked) => 
                        setNotifications(prev => ({ ...prev, [item.key]: checked }))
                      }
                    />
                  </div>
                ))}
              </div>
            </div>

            <div className="p-4 rounded-lg border border-border bg-card/50">
              <h3 className="font-medium mb-4">Delivery Methods</h3>
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="font-medium text-sm">Email Digest</p>
                    <p className="text-xs text-muted-foreground">Daily summary of all alerts</p>
                  </div>
                  <Switch 
                    checked={notifications.emailDigest}
                    onCheckedChange={(checked) => 
                      setNotifications(prev => ({ ...prev, emailDigest: checked }))
                    }
                  />
                </div>
                <div className="flex items-center justify-between">
                  <div>
                    <p className="font-medium text-sm">Browser Notifications</p>
                    <p className="text-xs text-muted-foreground">Push notifications in browser</p>
                  </div>
                  <Switch 
                    checked={notifications.browserNotifications}
                    onCheckedChange={(checked) => 
                      setNotifications(prev => ({ ...prev, browserNotifications: checked }))
                    }
                  />
                </div>
              </div>
            </div>
          </div>
        </TabsContent>

        <TabsContent value="security" className="mt-6">
          <div className="max-w-2xl space-y-6">
            <div className="p-4 rounded-lg border border-border bg-card/50">
              <h3 className="font-medium mb-4">Authentication</h3>
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="font-medium text-sm">Two-Factor Authentication</p>
                    <p className="text-xs text-muted-foreground">Require 2FA for login</p>
                  </div>
                  <Switch 
                    checked={security.twoFactor}
                    onCheckedChange={(checked) => 
                      setSecurity(prev => ({ ...prev, twoFactor: checked }))
                    }
                  />
                </div>
                
                <div>
                  <label className="text-sm font-medium">Session Timeout (minutes)</label>
                  <Input 
                    type="number"
                    value={security.sessionTimeout}
                    onChange={(e) => setSecurity(prev => ({ ...prev, sessionTimeout: e.target.value }))}
                    className="mt-1 max-w-xs"
                  />
                </div>

                <div className="flex items-center justify-between">
                  <div>
                    <p className="font-medium text-sm">IP Whitelist</p>
                    <p className="text-xs text-muted-foreground">Restrict access to specific IPs</p>
                  </div>
                  <Switch 
                    checked={security.ipWhitelist}
                    onCheckedChange={(checked) => 
                      setSecurity(prev => ({ ...prev, ipWhitelist: checked }))
                    }
                  />
                </div>
              </div>
            </div>

            <div className="p-4 rounded-lg border border-border bg-card/50">
              <h3 className="font-medium mb-4">API Keys</h3>
              <div className="space-y-3">
                <div className="flex items-center gap-3">
                  <Key className="w-4 h-4 text-muted-foreground" />
                  <code className="text-sm bg-secondary px-2 py-1 rounded flex-1">
                    psoc_api_••••••••••••••••
                  </code>
                  <Button variant="glass" size="sm">Regenerate</Button>
                </div>
              </div>
            </div>
          </div>
        </TabsContent>

        <TabsContent value="integrations" className="mt-6">
          <div className="max-w-2xl space-y-4">
            {[
              { name: 'AlienVault OTX', status: 'Connected', icon: Globe },
              { name: 'Recorded Future', status: 'Connected', icon: Database },
              { name: 'VirusTotal', status: 'Connected', icon: Shield },
              { name: 'CISA Alerts', status: 'Connected', icon: Bell },
              { name: 'Slack Notifications', status: 'Not Connected', icon: Users },
            ].map((integration) => {
              const Icon = integration.icon;
              return (
                <div 
                  key={integration.name}
                  className="p-4 rounded-lg border border-border bg-card/50 flex items-center justify-between"
                >
                  <div className="flex items-center gap-3">
                    <Icon className="w-5 h-5 text-primary" />
                    <div>
                      <p className="font-medium">{integration.name}</p>
                      <p className={`text-xs ${integration.status === 'Connected' ? 'text-success' : 'text-muted-foreground'}`}>
                        {integration.status}
                      </p>
                    </div>
                  </div>
                  <Button variant="glass" size="sm">
                    {integration.status === 'Connected' ? 'Configure' : 'Connect'}
                  </Button>
                </div>
              );
            })}
          </div>
        </TabsContent>

        <TabsContent value="appearance" className="mt-6">
          <div className="max-w-2xl space-y-6">
            <div className="p-4 rounded-lg border border-border bg-card/50">
              <h3 className="font-medium mb-4">Theme</h3>
              <div className="grid grid-cols-3 gap-4">
                <div className="p-4 rounded-lg border-2 border-primary bg-background text-center cursor-pointer">
                  <div className="w-8 h-8 mx-auto mb-2 rounded bg-primary/20" />
                  <p className="text-sm font-medium">Dark</p>
                </div>
                <div className="p-4 rounded-lg border border-border bg-secondary/30 text-center cursor-pointer opacity-50">
                  <div className="w-8 h-8 mx-auto mb-2 rounded bg-secondary" />
                  <p className="text-sm font-medium">Light</p>
                  <p className="text-xs text-muted-foreground">Coming soon</p>
                </div>
                <div className="p-4 rounded-lg border border-border bg-secondary/30 text-center cursor-pointer opacity-50">
                  <div className="w-8 h-8 mx-auto mb-2 rounded bg-gradient-to-r from-primary to-secondary" />
                  <p className="text-sm font-medium">System</p>
                  <p className="text-xs text-muted-foreground">Coming soon</p>
                </div>
              </div>
            </div>

            <div className="p-4 rounded-lg border border-border bg-card/50">
              <h3 className="font-medium mb-4">Dashboard Layout</h3>
              <p className="text-sm text-muted-foreground">
                Customize your dashboard layout and widget preferences in future updates.
              </p>
            </div>
          </div>
        </TabsContent>
      </Tabs>
    </div>
  );
}
