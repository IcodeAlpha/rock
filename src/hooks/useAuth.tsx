import { useState, useEffect, createContext, useContext, ReactNode } from 'react';
import { User, Session } from '@supabase/supabase-js';
import { supabase } from '@/integrations/supabase/client'; // ← Update this to your correct path

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
      console.log('🔍 Fetching org for user:', userId);
      
      const { data, error } = await supabase
        .from('organization_members')
        .select('organization_id, role')
        .eq('user_id', userId)
        .maybeSingle();

      if (error) {
        console.error('❌ Error fetching org membership:', error);
        return;
      }

      if (data) {
        console.log('✅ Found org:', data.organization_id, 'Role:', data.role);
        setOrganizationId(data.organization_id);
        setUserRole(data.role as 'admin' | 'analyst' | 'viewer');
      } else {
        console.log('⚠️ No organization found for user');
      }
    } catch (err) {
      console.error('❌ Error in fetchUserOrgAndRole:', err);
    }
  };

  useEffect(() => {
    const { data: { subscription } } = supabase.auth.onAuthStateChange(
      (event, session) => {
        console.log('🔐 Auth state changed:', event);
        setSession(session);
        setUser(session?.user ?? null);
        setLoading(false);

        if (session?.user) {
          setTimeout(() => {
            fetchUserOrgAndRole(session.user.id);
          }, 0);
        } else {
          setOrganizationId(null);
          setUserRole(null);
        }
      }
    );

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
      console.log('📝 Starting signup for:', email);
      const redirectUrl = `${window.location.origin}/`;

      // STEP 1: Sign up the user
      console.log('👤 Creating user account...');
      const { data: authData, error: authError } = await supabase.auth.signUp({
        email,
        password,
        options: {
          emailRedirectTo: redirectUrl,
          data: {
            full_name: fullName
          }
        }
      });

      if (authError) {
        console.error('❌ Auth error:', authError);
        alert(`Auth Error: ${authError.message}`); // TEMPORARY: Show error to user
        return { error: authError };
      }

      if (!authData.user || !authData.session) {
        console.error('❌ No user or session returned');
        alert('No user or session created'); // TEMPORARY
        return { error: new Error('Failed to create user session') };
      }

      console.log('✅ User created:', authData.user.id);
      console.log('✅ Session created:', authData.session.access_token.substring(0, 20) + '...');

      // STEP 2: Wait for profile trigger
      console.log('⏳ Waiting 2 seconds for profile trigger...');
      await new Promise(resolve => setTimeout(resolve, 2000));
      console.log('✅ Wait complete');

      // STEP 3: Create organization
      const orgSlug = orgName
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, '-')
        .replace(/(^-|-$)/g, '')
        .substring(0, 50);
      const uniqueSlug = `${orgSlug}-${Date.now().toString(36)}`;

      console.log('🏢 Creating organization:', { name: orgName, slug: uniqueSlug });

      const { data: orgData, error: orgError } = await supabase
        .from('organizations')
        .insert({ 
          name: orgName, 
          slug: uniqueSlug 
        })
        .select()
        .single();

      if (orgError) {
        console.error('❌ Organization error:', orgError);
        console.error('Error details:', {
          message: orgError.message,
          details: orgError.details,
          hint: orgError.hint,
          code: orgError.code
        });
        
        // TEMPORARY: Show full error to user
        alert(`Organization Error (${orgError.code}): ${orgError.message}\n\nDetails: ${orgError.details}\nHint: ${orgError.hint}`);
        
        return { error: new Error(`Failed to create organization: ${orgError.message}`) };
      }

      if (!orgData) {
        console.error('❌ No org data returned');
        alert('Organization created but no data returned');
        return { error: new Error('Organization created but no data returned') };
      }

      console.log('✅ Organization created:', orgData.id);

      // STEP 4: Add user as admin
      console.log('👥 Adding user to organization as admin...');
      const { error: memberError } = await supabase
        .from('organization_members')
        .insert({
          organization_id: orgData.id,
          user_id: authData.user.id,
          role: 'admin'
        });

      if (memberError) {
        console.error('❌ Member error:', memberError);
        console.error('Error details:', {
          message: memberError.message,
          details: memberError.details,
          hint: memberError.hint,
          code: memberError.code
        });
        
        // TEMPORARY: Show error
        alert(`Member Error (${memberError.code}): ${memberError.message}\n\nDetails: ${memberError.details}`);
        
        return { error: new Error(`Failed to add user to organization: ${memberError.message}`) };
      }

      console.log('✅ User added to organization as admin');
      console.log('🎉 Signup complete!');

      // STEP 5: Update local state
      setOrganizationId(orgData.id);
      setUserRole('admin');

      return { error: null };
    } catch (err) {
      console.error('❌ Unexpected error:', err);
      alert(`Unexpected error: ${err instanceof Error ? err.message : 'Unknown error'}`);
      return { error: err as Error };
    }
  };

  const signIn = async (email: string, password: string) => {
    try {
      const { error } = await supabase.auth.signInWithPassword({
        email,
        password
      });
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