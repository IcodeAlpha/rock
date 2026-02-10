import { useEffect, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { supabase } from '@/integrations/supabase/client';
import { useAuth } from '@/hooks/useAuth';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Separator } from '@/components/ui/separator';
import { toast } from 'sonner';
import { 
  Shield, Crown, FileEdit, Eye, CheckCircle, XCircle, 
  Loader2, AlertTriangle, LogIn, UserPlus, Building2
} from 'lucide-react';

type AppRole = 'admin' | 'analyst' | 'viewer';

interface InvitationDetails {
  id: string;
  email: string;
  role: AppRole;
  status: string;
  token: string;
  expires_at: string;
  organization_id: string;
  organization?: { name: string };
}

const ROLE_CONFIG = {
  admin: { icon: Crown, color: 'text-amber-500', bg: 'bg-amber-500/10', label: 'Administrator' },
  analyst: { icon: FileEdit, color: 'text-blue-500', bg: 'bg-blue-500/10', label: 'Analyst' },
  viewer: { icon: Eye, color: 'text-muted-foreground', bg: 'bg-muted', label: 'Viewer' },
};

type PageState = 'loading' | 'invalid' | 'expired' | 'already-accepted' | 'ready' | 'auth' | 'accepting' | 'success';
type AuthMode = 'login' | 'signup';

export function AcceptInvitePage() {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const { user } = useAuth();

  const token = searchParams.get('token');

  const [pageState, setPageState] = useState<PageState>('loading');
  const [invitation, setInvitation] = useState<InvitationDetails | null>(null);
  const [authMode, setAuthMode] = useState<AuthMode>('signup');

  // Auth form state
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [fullName, setFullName] = useState('');
  const [authLoading, setAuthLoading] = useState(false);
  const [authError, setAuthError] = useState('');

  // ─── 1. Load invitation by token ────────────────────────────────────────────
  useEffect(() => {
    if (!token) {
      setPageState('invalid');
      return;
    }
    loadInvitation();
  }, [token]);

  // ─── 2. Once user is logged in, try to accept automatically ─────────────────
  useEffect(() => {
    if (user && invitation && pageState === 'auth') {
      acceptInvitation();
    }
  }, [user, invitation]);

  const loadInvitation = async () => {
    try {
      const { data, error } = await supabase
        .from('invitations')
        .select('*, organization:organizations(name)')
        .eq('token', token)
        .single();

      if (error || !data) {
        setPageState('invalid');
        return;
      }

      const inv = data as InvitationDetails;

      if (inv.status === 'accepted') {
        setInvitation(inv);
        setPageState('already-accepted');
        return;
      }

      if (inv.status === 'cancelled' || inv.status === 'expired' || new Date(inv.expires_at) < new Date()) {
        setInvitation(inv);
        setPageState('expired');
        return;
      }

      setInvitation(inv);

      // Pre-fill the email field
      setEmail(inv.email);

      // If already logged in with matching email, go straight to accepting
      if (user && user.email?.toLowerCase() === inv.email.toLowerCase()) {
        setPageState('accepting');
        await acceptInvitation(inv);
      } else if (user) {
        // Logged in but wrong account — show mismatch warning still as 'ready'
        setPageState('ready');
      } else {
        setPageState('ready');
      }
    } catch (err) {
      console.error(err);
      setPageState('invalid');
    }
  };

  // ─── Accept invitation: add to org, mark accepted ───────────────────────────
  const acceptInvitation = async (inv?: InvitationDetails) => {
    const target = inv || invitation;
    if (!target || !user) return;

    setPageState('accepting');

    try {
      // Check not already a member
      const { data: existing } = await supabase
        .from('organization_members')
        .select('id')
        .eq('organization_id', target.organization_id)
        .eq('user_id', user.id)
        .single();

      if (!existing) {
        // Add to organization
        const { error: memberError } = await supabase
          .from('organization_members')
          .insert({
            organization_id: target.organization_id,
            user_id: user.id,
            role: target.role,
          });

        if (memberError) throw memberError;
      }

      // Mark invitation accepted
      await supabase
        .from('invitations')
        .update({ status: 'accepted' })
        .eq('id', target.id);

      setPageState('success');

      toast.success(`Welcome! You've joined as ${ROLE_CONFIG[target.role].label}`);

      // Redirect to dashboard after short delay
      setTimeout(() => navigate('/app'), 2000);
    } catch (err: any) {
      console.error(err);
      toast.error('Failed to accept invitation: ' + err.message);
      setPageState('ready');
    }
  };

  // ─── Auth: Login ────────────────────────────────────────────────────────────
  const handleLogin = async () => {
    if (!email || !password) return;
    setAuthLoading(true);
    setAuthError('');

    const { error } = await supabase.auth.signInWithPassword({ email, password });

    if (error) {
      setAuthError(error.message);
      setAuthLoading(false);
      return;
    }

    // useEffect will pick up the user change and call acceptInvitation
    setPageState('auth');
    setAuthLoading(false);
  };

  // ─── Auth: Sign Up ──────────────────────────────────────────────────────────
  const handleSignUp = async () => {
    if (!email || !password) return;
    setAuthLoading(true);
    setAuthError('');

    const { error } = await supabase.auth.signUp({
      email,
      password,
      options: {
        data: { full_name: fullName },
      },
    });

    if (error) {
      setAuthError(error.message);
      setAuthLoading(false);
      return;
    }

    // Supabase may require email confirmation — handle both cases
    setPageState('auth');
    setAuthLoading(false);
  };

  // ─── Renders ────────────────────────────────────────────────────────────────

  if (pageState === 'loading') {
    return (
      <div className="min-h-screen flex items-center justify-center bg-background">
        <div className="text-center space-y-4">
          <Loader2 className="w-10 h-10 animate-spin text-primary mx-auto" />
          <p className="text-muted-foreground">Verifying invitation...</p>
        </div>
      </div>
    );
  }

  if (pageState === 'accepting') {
    return (
      <div className="min-h-screen flex items-center justify-center bg-background">
        <div className="text-center space-y-4">
          <Loader2 className="w-10 h-10 animate-spin text-primary mx-auto" />
          <p className="text-muted-foreground">Accepting invitation...</p>
        </div>
      </div>
    );
  }

  if (pageState === 'success') {
    return (
      <div className="min-h-screen flex items-center justify-center bg-background p-4">
        <Card className="w-full max-w-md text-center">
          <CardContent className="pt-12 pb-8 space-y-4">
            <div className="w-16 h-16 rounded-full bg-green-500/10 flex items-center justify-center mx-auto">
              <CheckCircle className="w-8 h-8 text-green-500" />
            </div>
            <h2 className="text-2xl font-bold">You're in!</h2>
            <p className="text-muted-foreground">
              You've successfully joined <strong>{invitation?.organization?.name || 'the organization'}</strong>.
              Redirecting to your dashboard...
            </p>
            <Loader2 className="w-5 h-5 animate-spin text-muted-foreground mx-auto" />
          </CardContent>
        </Card>
      </div>
    );
  }

  if (pageState === 'invalid') {
    return (
      <div className="min-h-screen flex items-center justify-center bg-background p-4">
        <Card className="w-full max-w-md text-center">
          <CardContent className="pt-12 pb-8 space-y-4">
            <div className="w-16 h-16 rounded-full bg-destructive/10 flex items-center justify-center mx-auto">
              <XCircle className="w-8 h-8 text-destructive" />
            </div>
            <h2 className="text-2xl font-bold">Invalid Invitation</h2>
            <p className="text-muted-foreground">
              This invitation link is invalid or has already been used.
            </p>
            <Button onClick={() => navigate('/auth')} variant="outline">
              Go to Login
            </Button>
          </CardContent>
        </Card>
      </div>
    );
  }

  if (pageState === 'expired') {
    return (
      <div className="min-h-screen flex items-center justify-center bg-background p-4">
        <Card className="w-full max-w-md text-center">
          <CardContent className="pt-12 pb-8 space-y-4">
            <div className="w-16 h-16 rounded-full bg-orange-500/10 flex items-center justify-center mx-auto">
              <AlertTriangle className="w-8 h-8 text-orange-500" />
            </div>
            <h2 className="text-2xl font-bold">Invitation Expired</h2>
            <p className="text-muted-foreground">
              This invitation has expired or been cancelled. Please ask your admin to send a new one.
            </p>
            <Button onClick={() => navigate('/auth')} variant="outline">
              Go to Login
            </Button>
          </CardContent>
        </Card>
      </div>
    );
  }

  if (pageState === 'already-accepted') {
    return (
      <div className="min-h-screen flex items-center justify-center bg-background p-4">
        <Card className="w-full max-w-md text-center">
          <CardContent className="pt-12 pb-8 space-y-4">
            <div className="w-16 h-16 rounded-full bg-primary/10 flex items-center justify-center mx-auto">
              <CheckCircle className="w-8 h-8 text-primary" />
            </div>
            <h2 className="text-2xl font-bold">Already Accepted</h2>
            <p className="text-muted-foreground">
              This invitation has already been accepted. You're already a member of{' '}
              <strong>{invitation?.organization?.name || 'the organization'}</strong>.
            </p>
            <Button onClick={() => navigate('/app')}>Go to Dashboard</Button>
          </CardContent>
        </Card>
      </div>
    );
  }

  // ─── Main: ready state — show invite card + auth form ───────────────────────
  const roleConfig = invitation ? ROLE_CONFIG[invitation.role] : null;
  const RoleIcon = roleConfig?.icon || Eye;

  // If user is logged in but email doesn't match the invitation
  const emailMismatch = user && invitation && user.email?.toLowerCase() !== invitation.email.toLowerCase();

  return (
    <div className="min-h-screen flex items-center justify-center bg-background p-4">
      <div className="w-full max-w-md space-y-4">

        {/* Branding */}
        <div className="text-center space-y-2">
          <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-blue-500 to-violet-600 flex items-center justify-center mx-auto shadow-lg shadow-blue-500/25">
            <Shield className="w-6 h-6 text-white" />
          </div>
          <p className="text-sm text-muted-foreground font-medium tracking-widest uppercase">PSOC</p>
        </div>

        {/* Invitation Summary Card */}
        {invitation && (
          <Card className="border-primary/20">
            <CardHeader className="pb-3">
              <CardTitle className="text-lg">You've been invited</CardTitle>
              <CardDescription>Review the details below before accepting</CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="flex items-center gap-3 p-3 rounded-lg bg-muted/50">
                <Building2 className="w-5 h-5 text-muted-foreground shrink-0" />
                <div>
                  <p className="text-xs text-muted-foreground">Organization</p>
                  <p className="font-semibold">{invitation.organization?.name || 'Unknown'}</p>
                </div>
              </div>
              <div className="flex items-center gap-3 p-3 rounded-lg bg-muted/50">
                <div className={`w-8 h-8 rounded-lg ${roleConfig?.bg} flex items-center justify-center shrink-0`}>
                  <RoleIcon className={`w-4 h-4 ${roleConfig?.color}`} />
                </div>
                <div>
                  <p className="text-xs text-muted-foreground">Your Role</p>
                  <p className="font-semibold">{roleConfig?.label}</p>
                </div>
              </div>
              <div className="flex items-center gap-3 p-3 rounded-lg bg-muted/50">
                <div className="w-8 h-8 rounded-full bg-primary/10 flex items-center justify-center shrink-0 text-xs font-bold text-primary">
                  @
                </div>
                <div>
                  <p className="text-xs text-muted-foreground">Invited Email</p>
                  <p className="font-semibold">{invitation.email}</p>
                </div>
              </div>
            </CardContent>
          </Card>
        )}

        {/* Email mismatch warning */}
        {emailMismatch && (
          <Card className="border-orange-500/50 bg-orange-500/5">
            <CardContent className="pt-4 pb-4">
              <div className="flex gap-3">
                <AlertTriangle className="w-5 h-5 text-orange-500 shrink-0 mt-0.5" />
                <div className="text-sm">
                  <p className="font-medium text-orange-500">Account mismatch</p>
                  <p className="text-muted-foreground mt-1">
                    You're signed in as <strong>{user?.email}</strong>, but this invite is for{' '}
                    <strong>{invitation?.email}</strong>. Please sign out and log in with the correct account.
                  </p>
                  <Button
                    variant="outline"
                    size="sm"
                    className="mt-3 border-orange-500/50"
                    onClick={() => supabase.auth.signOut()}
                  >
                    Sign Out
                  </Button>
                </div>
              </div>
            </CardContent>
          </Card>
        )}

        {/* Auth form — only show if not logged in (or mismatch) */}
        {!user || emailMismatch ? (
          <Card>
            <CardHeader className="pb-3">
              <div className="flex gap-1 p-1 bg-muted rounded-lg">
                <button
                  className={`flex-1 py-1.5 text-sm font-medium rounded-md transition-colors ${
                    authMode === 'signup' ? 'bg-background shadow-sm text-foreground' : 'text-muted-foreground'
                  }`}
                  onClick={() => setAuthMode('signup')}
                >
                  Create Account
                </button>
                <button
                  className={`flex-1 py-1.5 text-sm font-medium rounded-md transition-colors ${
                    authMode === 'login' ? 'bg-background shadow-sm text-foreground' : 'text-muted-foreground'
                  }`}
                  onClick={() => setAuthMode('login')}
                >
                  Sign In
                </button>
              </div>
            </CardHeader>

            <CardContent className="space-y-3">
              {authMode === 'signup' && (
                <div className="space-y-1.5">
                  <Label htmlFor="fullName">Full Name</Label>
                  <Input
                    id="fullName"
                    placeholder="Jane Smith"
                    value={fullName}
                    onChange={(e) => setFullName(e.target.value)}
                  />
                </div>
              )}

              <div className="space-y-1.5">
                <Label htmlFor="authEmail">Email</Label>
                <Input
                  id="authEmail"
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  // Lock the email to the invited address
                  readOnly={!!invitation?.email}
                  className={invitation?.email ? 'bg-muted cursor-not-allowed' : ''}
                />
                {invitation?.email && (
                  <p className="text-xs text-muted-foreground">Email must match your invitation</p>
                )}
              </div>

              <div className="space-y-1.5">
                <Label htmlFor="password">Password</Label>
                <Input
                  id="password"
                  type="password"
                  placeholder={authMode === 'signup' ? 'Create a password (min 6 chars)' : 'Your password'}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') {
                      authMode === 'login' ? handleLogin() : handleSignUp();
                    }
                  }}
                />
              </div>

              {authError && (
                <div className="flex items-center gap-2 p-3 rounded-lg bg-destructive/10 text-destructive text-sm">
                  <AlertTriangle className="w-4 h-4 shrink-0" />
                  {authError}
                </div>
              )}
            </CardContent>

            <CardFooter>
              <Button
                className="w-full gap-2"
                onClick={authMode === 'login' ? handleLogin : handleSignUp}
                disabled={authLoading || !email || !password}
              >
                {authLoading && <Loader2 className="w-4 h-4 animate-spin" />}
                {authMode === 'login' ? (
                  <><LogIn className="w-4 h-4" /> Sign In & Accept</>
                ) : (
                  <><UserPlus className="w-4 h-4" /> Create Account & Accept</>
                )}
              </Button>
            </CardFooter>
          </Card>
        ) : (
          /* User is logged in with matching email — show accept button */
          <Card>
            <CardContent className="pt-6 pb-6 space-y-4 text-center">
              <p className="text-muted-foreground text-sm">
                Signed in as <strong className="text-foreground">{user.email}</strong>
              </p>
              <Button
                className="w-full gap-2"
                onClick={() => acceptInvitation()}
              >
                <CheckCircle className="w-4 h-4" />
                Accept Invitation
              </Button>
              <button
                className="text-xs text-muted-foreground underline-offset-2 hover:underline"
                onClick={() => supabase.auth.signOut()}
              >
                Sign out and use a different account
              </button>
            </CardContent>
          </Card>
        )}
      </div>
    </div>
  );
}