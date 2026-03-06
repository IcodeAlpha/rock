import { useState, useEffect, createContext, useContext, ReactNode } from 'react';
import { User, Session } from '@supabase/supabase-js';
import { supabase } from '@/integrations/supabase/client';

interface AuthContextType {
  user: User | null;
  session: Session | null;
  loading: boolean;
  organizationId: string | null;
  userRole: 'admin' | 'analyst' | 'viewer' | null;
  signUp: (email: string, password: string, fullName: string, orgName: string) => Promise<{ error: Error | null }>;
  signIn: (email: string, password: string) => Promise<{ error: Error | null }>;
  signOut: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider = ({ children }: { children: ReactNode }) => {
  const [user, setUser] = useState<User | null>(null);
  const [session, setSession] = useState<Session | null>(null);
  const [loading, setLoading] = useState(true);
  const [organizationId, setOrganizationId] = useState<string | null>(null);
  const [userRole, setUserRole] = useState<'admin' | 'analyst' | 'viewer' | null>(null);

  const fetchUserOrgAndRole = async (userId: string) => {
    try {
      const { data, error } = await supabase
        .from('organization_members')
        .select('organization_id, role')
        .eq('user_id', userId)
        .maybeSingle();

      if (error) {
        console.error('Error fetching org membership:', error);
        return;
      }

      if (data) {
        setOrganizationId(data.organization_id);
        setUserRole(data.role as 'admin' | 'analyst' | 'viewer');
      }
    } catch (err) {
      console.error('Error in fetchUserOrgAndRole:', err);
    }
  };

  useEffect(() => {
    // Set up auth state listener FIRST
    const { data: { subscription } } = supabase.auth.onAuthStateChange(
      (event, session) => {
        setSession(session);
        setUser(session?.user ?? null);
        setLoading(false);

        if (session?.user) {
          // Defer Supabase calls to avoid deadlock inside auth callback
          setTimeout(() => {
            fetchUserOrgAndRole(session.user.id);
          }, 0);
        } else {
          setOrganizationId(null);
          setUserRole(null);
        }
      }
    );

    // THEN check for an existing session
    supabase.auth.getSession().then(({ data: { session } }) => {
      setSession(session);
      setUser(session?.user ?? null);
      setLoading(false);

      if (session?.user) {
        fetchUserOrgAndRole(session.user.id);
      }
    });

    return () => subscription.unsubscribe();
  }, []);

  const signUp = async (email: string, password: string, fullName: string, orgName: string) => {
    try {
      const redirectUrl = `${window.location.origin}/`;

      // STEP 1: Create the user account
      const { data: authData, error: authError } = await supabase.auth.signUp({
        email,
        password,
        options: {
          emailRedirectTo: redirectUrl,
          data: { full_name: fullName }
        }
      });

      if (authError) return { error: authError };

      // v1: require both user AND session before proceeding
      if (!authData.user || !authData.session) {
        return { error: new Error('Failed to create user session') };
      }

      // STEP 2: Wait for the DB profile trigger to fire
      await new Promise(resolve => setTimeout(resolve, 2000));

      // STEP 3: Create the organization with a unique slug
      const orgSlug = orgName
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, '-')
        .replace(/(^-|-$)/g, '')
        .substring(0, 50);
      const uniqueSlug = `${orgSlug}-${Date.now().toString(36)}`;

      const { data: orgData, error: orgError } = await supabase
        .from('organizations')
        .insert({ name: orgName, slug: uniqueSlug })
        .select()
        .single();

      if (orgError) {
        console.error('Error creating organization:', orgError);
        return { error: new Error(`Failed to create organization: ${orgError.message}`) };
      }

      if (!orgData) {
        return { error: new Error('Organization created but no data returned') };
      }

      // STEP 4: Add the user as admin of the new org
      const { error: memberError } = await supabase
        .from('organization_members')
        .insert({
          organization_id: orgData.id,
          user_id: authData.user.id,
          role: 'admin'
        });

      if (memberError) {
        console.error('Error adding user to organization:', memberError);
        return { error: new Error(`Failed to add user to organization: ${memberError.message}`) };
      }

      // STEP 5: Sync local state immediately so the app doesn't need a reload
      setOrganizationId(orgData.id);
      setUserRole('admin');

      return { error: null };
    } catch (err) {
      return { error: err as Error };
    }
  };

  const signIn = async (email: string, password: string) => {
    try {
      const { error } = await supabase.auth.signInWithPassword({ email, password });
      return { error };
    } catch (err) {
      return { error: err as Error };
    }
  };

  const signOut = async () => {
    await supabase.auth.signOut();
    setOrganizationId(null);
    setUserRole(null);
  };

  return (
    <AuthContext.Provider value={{
      user,
      session,
      loading,
      organizationId,
      userRole,
      signUp,
      signIn,
      signOut
    }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};