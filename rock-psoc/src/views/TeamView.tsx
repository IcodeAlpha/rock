import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { supabase } from '@/integrations/supabase/client';
import { useOrganization } from '@/hooks/useOrganization';
import { useAuth } from '@/hooks/useAuth';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle, AlertDialogTrigger } from '@/components/ui/alert-dialog';
import { toast } from 'sonner';
import { 
  Users, UserPlus, Shield, Eye, Pencil, Trash2, Loader2, Crown, 
  Mail, Clock, CheckCircle, XCircle, RefreshCw, Copy, AlertTriangle,
  ShieldCheck, FileEdit, Search
} from 'lucide-react';
import { format, formatDistanceToNow } from 'date-fns';

type AppRole = 'admin' | 'analyst' | 'viewer';

interface TeamMember {
  id: string;
  user_id: string;
  role: AppRole;
  created_at: string;
  profile: {
    email: string;
    full_name: string | null;
    avatar_url: string | null;
  } | null;
}

interface Invitation {
  id: string;
  email: string;
  role: AppRole;
  status: string;
  created_at: string;
  expires_at: string;
  invited_by: string | null;
}

const ROLE_PERMISSIONS = {
  admin: {
    icon: Crown,
    color: 'text-amber-500',
    bgColor: 'bg-amber-500/10',
    label: 'Administrator',
    description: 'Full access to all features',
    permissions: [
      'Manage team members and invitations',
      'Create, edit, and delete all data',
      'Configure organization settings',
      'Generate and schedule reports',
      'Access all security features'
    ]
  },
  analyst: {
    icon: FileEdit,
    color: 'text-blue-500',
    bgColor: 'bg-blue-500/10',
    label: 'Analyst',
    description: 'Can create and modify data',
    permissions: [
      'Create and edit incidents, alerts, predictions',
      'Generate reports',
      'Query OSINT sources',
      'View all organization data',
      'Cannot manage team or settings'
    ]
  },
  viewer: {
    icon: Eye,
    color: 'text-muted-foreground',
    bgColor: 'bg-muted',
    label: 'Viewer',
    description: 'Read-only access',
    permissions: [
      'View dashboard and statistics',
      'View incidents and alerts',
      'View predictions and reports',
      'Cannot create or modify data',
      'Cannot manage team or settings'
    ]
  }
};

export function TeamView() {
  const { organizationId, isAdmin } = useOrganization();
  const { user } = useAuth();
  const queryClient = useQueryClient();
  const [inviteOpen, setInviteOpen] = useState(false);
  const [inviteEmail, setInviteEmail] = useState('');
  const [inviteRole, setInviteRole] = useState<AppRole>('viewer');
  const [editingMember, setEditingMember] = useState<TeamMember | null>(null);
  const [newRole, setNewRole] = useState<AppRole>('viewer');
  const [searchQuery, setSearchQuery] = useState('');

  // Fetch team members
  const { data: members, isLoading: membersLoading } = useQuery({
    queryKey: ['team-members', organizationId],
    queryFn: async () => {
      if (!organizationId) return [];
      
      const { data, error } = await supabase
        .from('organization_members')
        .select('id, user_id, role, created_at')
        .eq('organization_id', organizationId);
      
      if (error) throw error;

      const membersWithProfiles = await Promise.all(
        data.map(async (member) => {
          const { data: profile } = await supabase
            .from('profiles')
            .select('email, full_name, avatar_url')
            .eq('id', member.user_id)
            .single();
          
          return { ...member, profile } as TeamMember;
        })
      );

      return membersWithProfiles;
    },
    enabled: !!organizationId
  });

  // Fetch pending invitations
  const { data: invitations, isLoading: invitationsLoading } = useQuery({
    queryKey: ['invitations', organizationId],
    queryFn: async () => {
      if (!organizationId) return [];
      
      const { data, error } = await supabase
        .from('invitations')
        .select('*')
        .eq('organization_id', organizationId)
        .order('created_at', { ascending: false });
      
      if (error) throw error;
      return data as Invitation[];
    },
    enabled: !!organizationId && isAdmin
  });

  // Create invitation mutation
  const createInviteMutation = useMutation({
    mutationFn: async ({ email, role }: { email: string; role: AppRole }) => {
      if (!organizationId || !user) throw new Error('Missing organization or user');
      
      const { error } = await supabase
        .from('invitations')
        .insert({
          organization_id: organizationId,
          email: email.toLowerCase().trim(),
          role,
          invited_by: user.id
        });
      
      if (error) throw error;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['invitations'] });
      toast.success('Invitation created successfully');
      setInviteOpen(false);
      setInviteEmail('');
      setInviteRole('viewer');
    },
    onError: (error: Error) => {
      if (error.message.includes('duplicate')) {
        toast.error('An invitation for this email already exists');
      } else {
        toast.error('Failed to create invitation: ' + error.message);
      }
    }
  });

  // Cancel invitation mutation
  const cancelInviteMutation = useMutation({
    mutationFn: async (invitationId: string) => {
      const { error } = await supabase
        .from('invitations')
        .update({ status: 'cancelled' })
        .eq('id', invitationId);
      
      if (error) throw error;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['invitations'] });
      toast.success('Invitation cancelled');
    },
    onError: (error) => {
      toast.error('Failed to cancel invitation: ' + error.message);
    }
  });

  // Resend invitation mutation
  const resendInviteMutation = useMutation({
    mutationFn: async (invitation: Invitation) => {
      const { error: deleteError } = await supabase
        .from('invitations')
        .delete()
        .eq('id', invitation.id);
      
      if (deleteError) throw deleteError;

      const { error: insertError } = await supabase
        .from('invitations')
        .insert({
          organization_id: organizationId,
          email: invitation.email,
          role: invitation.role,
          invited_by: user?.id
        });
      
      if (insertError) throw insertError;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['invitations'] });
      toast.success('Invitation resent');
    },
    onError: (error) => {
      toast.error('Failed to resend invitation: ' + error.message);
    }
  });

  // Update role mutation
  const updateRoleMutation = useMutation({
    mutationFn: async ({ memberId, role }: { memberId: string; role: AppRole }) => {
      const { error } = await supabase
        .from('organization_members')
        .update({ role })
        .eq('id', memberId);
      
      if (error) throw error;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['team-members'] });
      toast.success('Role updated successfully');
      setEditingMember(null);
    },
    onError: (error) => {
      toast.error('Failed to update role: ' + error.message);
    }
  });

  // Remove member mutation
  const removeMemberMutation = useMutation({
    mutationFn: async (memberId: string) => {
      const { error } = await supabase
        .from('organization_members')
        .delete()
        .eq('id', memberId);
      
      if (error) throw error;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['team-members'] });
      toast.success('Member removed successfully');
    },
    onError: (error) => {
      toast.error('Failed to remove member: ' + error.message);
    }
  });

  const getRoleBadge = (role: AppRole) => {
    const config = ROLE_PERMISSIONS[role];
    const Icon = config.icon;
    
    return (
      <Badge variant={role === 'admin' ? 'default' : role === 'analyst' ? 'secondary' : 'outline'} className="capitalize flex items-center w-fit gap-1">
        <Icon className="w-3 h-3" />
        {role}
      </Badge>
    );
  };

  const getStatusBadge = (status: string, expiresAt: string) => {
    const isExpired = new Date(expiresAt) < new Date();
    
    if (status === 'accepted') {
      return <Badge variant="default" className="gap-1"><CheckCircle className="w-3 h-3" /> Accepted</Badge>;
    }
    if (status === 'cancelled') {
      return <Badge variant="destructive" className="gap-1"><XCircle className="w-3 h-3" /> Cancelled</Badge>;
    }
    if (isExpired || status === 'expired') {
      return <Badge variant="outline" className="gap-1 text-muted-foreground"><Clock className="w-3 h-3" /> Expired</Badge>;
    }
    return <Badge variant="secondary" className="gap-1"><Mail className="w-3 h-3" /> Pending</Badge>;
  };

  const getInitials = (name: string | null, email: string) => {
    if (name) {
      return name.split(' ').map(n => n[0]).join('').toUpperCase().slice(0, 2);
    }
    return email.slice(0, 2).toUpperCase();
  };

  const filteredMembers = members?.filter(member => {
    if (!searchQuery) return true;
    const query = searchQuery.toLowerCase();
    return (
      member.profile?.email?.toLowerCase().includes(query) ||
      member.profile?.full_name?.toLowerCase().includes(query) ||
      member.role.toLowerCase().includes(query)
    );
  });

  const pendingInvitations = invitations?.filter(i => i.status === 'pending' && new Date(i.expires_at) > new Date()) || [];
  const pastInvitations = invitations?.filter(i => i.status !== 'pending' || new Date(i.expires_at) <= new Date()) || [];

  const totalMembers = members?.length || 0;
  const adminCount = members?.filter(m => m.role === 'admin').length || 0;
  const analystCount = members?.filter(m => m.role === 'analyst').length || 0;
  const viewerCount = members?.filter(m => m.role === 'viewer').length || 0;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Team Management</h1>
          <p className="text-muted-foreground mt-1">
            {isAdmin ? 'Manage team members and their access levels' : 'View team members and their roles'}
          </p>
        </div>
        
        {isAdmin && (
          <Dialog open={inviteOpen} onOpenChange={setInviteOpen}>
            <DialogTrigger asChild>
              <Button className="gap-2">
                <UserPlus className="w-4 h-4" />
                Invite Member
              </Button>
            </DialogTrigger>
            <DialogContent>
              <DialogHeader>
                <DialogTitle>Invite Team Member</DialogTitle>
                <DialogDescription>
                  Create an invitation for a new team member
                </DialogDescription>
              </DialogHeader>
              <div className="space-y-4 py-4">
                <div className="space-y-2">
                  <Label htmlFor="email">Email Address</Label>
                  <Input
                    id="email"
                    type="email"
                    placeholder="colleague@company.com"
                    value={inviteEmail}
                    onChange={(e) => setInviteEmail(e.target.value)}
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="role">Role</Label>
                  <Select value={inviteRole} onValueChange={(v) => setInviteRole(v as AppRole)}>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {Object.entries(ROLE_PERMISSIONS).map(([role, config]) => {
                        const Icon = config.icon;
                        return (
                          <SelectItem key={role} value={role}>
                            <div className="flex items-center gap-2">
                              <Icon className={`w-4 h-4 ${config.color}`} />
                              <span>{config.label}</span>
                              <span className="text-muted-foreground">- {config.description}</span>
                            </div>
                          </SelectItem>
                        );
                      })}
                    </SelectContent>
                  </Select>
                </div>

                {/* Role permissions preview */}
                <div className={`p-3 rounded-lg ${ROLE_PERMISSIONS[inviteRole].bgColor}`}>
                  <p className="text-sm font-medium mb-2">This role can:</p>
                  <ul className="text-sm text-muted-foreground space-y-1">
                    {ROLE_PERMISSIONS[inviteRole].permissions.slice(0, 3).map((perm, i) => (
                      <li key={i} className="flex items-center gap-2">
                        <CheckCircle className="w-3 h-3 text-green-500" />
                        {perm}
                      </li>
                    ))}
                  </ul>
                </div>
              </div>
              <DialogFooter>
                <Button variant="outline" onClick={() => setInviteOpen(false)}>
                  Cancel
                </Button>
                <Button 
                  onClick={() => createInviteMutation.mutate({ email: inviteEmail, role: inviteRole })} 
                  disabled={!inviteEmail || createInviteMutation.isPending}
                >
                  {createInviteMutation.isPending && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
                  Create Invitation
                </Button>
              </DialogFooter>
            </DialogContent>
          </Dialog>
        )}
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-4">
              <div className="p-3 rounded-lg bg-primary/10">
                <Users className="w-6 h-6 text-primary" />
              </div>
              <div>
                <p className="text-2xl font-bold">{totalMembers}</p>
                <p className="text-sm text-muted-foreground">Total Members</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-4">
              <div className={`p-3 rounded-lg ${ROLE_PERMISSIONS.admin.bgColor}`}>
                <Crown className={`w-6 h-6 ${ROLE_PERMISSIONS.admin.color}`} />
              </div>
              <div>
                <p className="text-2xl font-bold">{adminCount}</p>
                <p className="text-sm text-muted-foreground">Admins</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-4">
              <div className={`p-3 rounded-lg ${ROLE_PERMISSIONS.analyst.bgColor}`}>
                <FileEdit className={`w-6 h-6 ${ROLE_PERMISSIONS.analyst.color}`} />
              </div>
              <div>
                <p className="text-2xl font-bold">{analystCount}</p>
                <p className="text-sm text-muted-foreground">Analysts</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-4">
              <div className={`p-3 rounded-lg ${ROLE_PERMISSIONS.viewer.bgColor}`}>
                <Eye className={`w-6 h-6 ${ROLE_PERMISSIONS.viewer.color}`} />
              </div>
              <div>
                <p className="text-2xl font-bold">{viewerCount}</p>
                <p className="text-sm text-muted-foreground">Viewers</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Main Content with Tabs */}
      <Tabs defaultValue="members" className="space-y-4">
        <TabsList>
          <TabsTrigger value="members" className="gap-2">
            <Users className="w-4 h-4" />
            Members ({totalMembers})
          </TabsTrigger>
          {isAdmin && (
            <TabsTrigger value="invitations" className="gap-2">
              <Mail className="w-4 h-4" />
              Invitations ({pendingInvitations.length})
            </TabsTrigger>
          )}
          <TabsTrigger value="roles" className="gap-2">
            <Shield className="w-4 h-4" />
            Role Permissions
          </TabsTrigger>
        </TabsList>

        {/* Members Tab */}
        <TabsContent value="members">
          <Card>
            <CardHeader>
              <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
                <div>
                  <CardTitle>Team Members</CardTitle>
                  <CardDescription>All members of your organization</CardDescription>
                </div>
                <div className="relative w-full sm:w-64">
                  <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                  <Input
                    placeholder="Search members..."
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    className="pl-9"
                  />
                </div>
              </div>
            </CardHeader>
            <CardContent>
              {membersLoading ? (
                <div className="flex items-center justify-center py-8">
                  <Loader2 className="w-6 h-6 animate-spin text-muted-foreground" />
                </div>
              ) : filteredMembers?.length === 0 ? (
                <div className="text-center py-8 text-muted-foreground">
                  {searchQuery ? 'No members match your search' : 'No team members yet'}
                </div>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Member</TableHead>
                      <TableHead>Role</TableHead>
                      <TableHead>Joined</TableHead>
                      {isAdmin && <TableHead className="text-right">Actions</TableHead>}
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {filteredMembers?.map((member) => (
                      <TableRow key={member.id}>
                        <TableCell>
                          <div className="flex items-center gap-3">
                            <Avatar>
                              <AvatarImage src={member.profile?.avatar_url || undefined} />
                              <AvatarFallback>
                                {getInitials(member.profile?.full_name || null, member.profile?.email || '')}
                              </AvatarFallback>
                            </Avatar>
                            <div>
                              <p className="font-medium">
                                {member.profile?.full_name || 'Unknown'}
                                {member.user_id === user?.id && (
                                  <Badge variant="outline" className="ml-2 text-xs">You</Badge>
                                )}
                              </p>
                              <p className="text-sm text-muted-foreground">{member.profile?.email}</p>
                            </div>
                          </div>
                        </TableCell>
                        <TableCell>{getRoleBadge(member.role)}</TableCell>
                        <TableCell className="text-muted-foreground">
                          {format(new Date(member.created_at), 'MMM d, yyyy')}
                        </TableCell>
                        {isAdmin && (
                          <TableCell className="text-right">
                            {member.user_id !== user?.id && (
                              <div className="flex items-center justify-end gap-2">
                                <Dialog 
                                  open={editingMember?.id === member.id} 
                                  onOpenChange={(open) => {
                                    if (open) {
                                      setEditingMember(member);
                                      setNewRole(member.role);
                                    } else {
                                      setEditingMember(null);
                                    }
                                  }}
                                >
                                  <DialogTrigger asChild>
                                    <Button variant="ghost" size="sm" title="Change role">
                                      <Pencil className="w-4 h-4" />
                                    </Button>
                                  </DialogTrigger>
                                  <DialogContent>
                                    <DialogHeader>
                                      <DialogTitle>Change Role</DialogTitle>
                                      <DialogDescription>
                                        Update the role for {member.profile?.full_name || member.profile?.email}
                                      </DialogDescription>
                                    </DialogHeader>
                                    <div className="py-4 space-y-4">
                                      <Select value={newRole} onValueChange={(v) => setNewRole(v as AppRole)}>
                                        <SelectTrigger>
                                          <SelectValue />
                                        </SelectTrigger>
                                        <SelectContent>
                                          {Object.entries(ROLE_PERMISSIONS).map(([role, config]) => {
                                            const Icon = config.icon;
                                            return (
                                              <SelectItem key={role} value={role}>
                                                <div className="flex items-center gap-2">
                                                  <Icon className={`w-4 h-4 ${config.color}`} />
                                                  <span>{config.label}</span>
                                                </div>
                                              </SelectItem>
                                            );
                                          })}
                                        </SelectContent>
                                      </Select>

                                      <div className={`p-3 rounded-lg ${ROLE_PERMISSIONS[newRole].bgColor}`}>
                                        <p className="text-sm font-medium mb-2">{ROLE_PERMISSIONS[newRole].label} permissions:</p>
                                        <ul className="text-sm text-muted-foreground space-y-1">
                                          {ROLE_PERMISSIONS[newRole].permissions.map((perm, i) => (
                                            <li key={i} className="flex items-center gap-2">
                                              <CheckCircle className="w-3 h-3 text-green-500 shrink-0" />
                                              {perm}
                                            </li>
                                          ))}
                                        </ul>
                                      </div>
                                    </div>
                                    <DialogFooter>
                                      <Button variant="outline" onClick={() => setEditingMember(null)}>
                                        Cancel
                                      </Button>
                                      <Button 
                                        onClick={() => updateRoleMutation.mutate({ memberId: member.id, role: newRole })}
                                        disabled={updateRoleMutation.isPending || newRole === member.role}
                                      >
                                        {updateRoleMutation.isPending && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
                                        Save Changes
                                      </Button>
                                    </DialogFooter>
                                  </DialogContent>
                                </Dialog>
                                
                                <AlertDialog>
                                  <AlertDialogTrigger asChild>
                                    <Button variant="ghost" size="sm" className="text-destructive hover:text-destructive" title="Remove member">
                                      <Trash2 className="w-4 h-4" />
                                    </Button>
                                  </AlertDialogTrigger>
                                  <AlertDialogContent>
                                    <AlertDialogHeader>
                                      <AlertDialogTitle>Remove Team Member</AlertDialogTitle>
                                      <AlertDialogDescription>
                                        Are you sure you want to remove {member.profile?.full_name || member.profile?.email} from the organization? This action cannot be undone.
                                      </AlertDialogDescription>
                                    </AlertDialogHeader>
                                    <AlertDialogFooter>
                                      <AlertDialogCancel>Cancel</AlertDialogCancel>
                                      <AlertDialogAction
                                        onClick={() => removeMemberMutation.mutate(member.id)}
                                        className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
                                      >
                                        {removeMemberMutation.isPending && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
                                        Remove
                                      </AlertDialogAction>
                                    </AlertDialogFooter>
                                  </AlertDialogContent>
                                </AlertDialog>
                              </div>
                            )}
                          </TableCell>
                        )}
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* Invitations Tab */}
        {isAdmin && (
          <TabsContent value="invitations">
            <div className="space-y-6">
              {/* Pending Invitations */}
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Mail className="w-5 h-5" />
                    Pending Invitations
                  </CardTitle>
                  <CardDescription>
                    Invitations waiting to be accepted
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  {invitationsLoading ? (
                    <div className="flex items-center justify-center py-8">
                      <Loader2 className="w-6 h-6 animate-spin text-muted-foreground" />
                    </div>
                  ) : pendingInvitations.length === 0 ? (
                    <div className="text-center py-8 text-muted-foreground">
                      <Mail className="w-12 h-12 mx-auto mb-3 opacity-50" />
                      <p>No pending invitations</p>
                      <Button variant="outline" className="mt-4" onClick={() => setInviteOpen(true)}>
                        <UserPlus className="w-4 h-4 mr-2" />
                        Invite Someone
                      </Button>
                    </div>
                  ) : (
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead>Email</TableHead>
                          <TableHead>Role</TableHead>
                          <TableHead>Expires</TableHead>
                          <TableHead className="text-right">Actions</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {pendingInvitations.map((invitation) => (
                          <TableRow key={invitation.id}>
                            <TableCell className="font-medium">{invitation.email}</TableCell>
                            <TableCell>{getRoleBadge(invitation.role)}</TableCell>
                            <TableCell className="text-muted-foreground">
                              {formatDistanceToNow(new Date(invitation.expires_at), { addSuffix: true })}
                            </TableCell>
                            <TableCell className="text-right">
                              <div className="flex items-center justify-end gap-2">
                                <Button
                                  variant="ghost"
                                  size="sm"
                                  onClick={() => resendInviteMutation.mutate(invitation)}
                                  disabled={resendInviteMutation.isPending}
                                  title="Resend invitation"
                                >
                                  <RefreshCw className="w-4 h-4" />
                                </Button>
                                <Button
                                  variant="ghost"
                                  size="sm"
                                  className="text-destructive hover:text-destructive"
                                  onClick={() => cancelInviteMutation.mutate(invitation.id)}
                                  disabled={cancelInviteMutation.isPending}
                                  title="Cancel invitation"
                                >
                                  <XCircle className="w-4 h-4" />
                                </Button>
                              </div>
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  )}
                </CardContent>
              </Card>

              {/* Past Invitations */}
              {pastInvitations.length > 0 && (
                <Card>
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2 text-muted-foreground">
                      <Clock className="w-5 h-5" />
                      Invitation History
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead>Email</TableHead>
                          <TableHead>Role</TableHead>
                          <TableHead>Status</TableHead>
                          <TableHead>Date</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {pastInvitations.slice(0, 10).map((invitation) => (
                          <TableRow key={invitation.id} className="opacity-60">
                            <TableCell>{invitation.email}</TableCell>
                            <TableCell>{getRoleBadge(invitation.role)}</TableCell>
                            <TableCell>{getStatusBadge(invitation.status, invitation.expires_at)}</TableCell>
                            <TableCell className="text-muted-foreground">
                              {format(new Date(invitation.created_at), 'MMM d, yyyy')}
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </CardContent>
                </Card>
              )}
            </div>
          </TabsContent>
        )}

        {/* Role Permissions Tab */}
        <TabsContent value="roles">
          <div className="grid gap-6 md:grid-cols-3">
            {Object.entries(ROLE_PERMISSIONS).map(([role, config]) => {
              const Icon = config.icon;
              return (
                <Card key={role} className={role === 'admin' ? 'border-amber-500/50' : ''}>
                  <CardHeader>
                    <div className={`w-12 h-12 rounded-lg ${config.bgColor} flex items-center justify-center mb-2`}>
                      <Icon className={`w-6 h-6 ${config.color}`} />
                    </div>
                    <CardTitle>{config.label}</CardTitle>
                    <CardDescription>{config.description}</CardDescription>
                  </CardHeader>
                  <CardContent>
                    <ul className="space-y-2">
                      {config.permissions.map((perm, i) => (
                        <li key={i} className="flex items-start gap-2 text-sm">
                          {perm.includes('Cannot') ? (
                            <XCircle className="w-4 h-4 text-destructive shrink-0 mt-0.5" />
                          ) : (
                            <CheckCircle className="w-4 h-4 text-green-500 shrink-0 mt-0.5" />
                          )}
                          <span className={perm.includes('Cannot') ? 'text-muted-foreground' : ''}>
                            {perm}
                          </span>
                        </li>
                      ))}
                    </ul>
                  </CardContent>
                </Card>
              );
            })}
          </div>
        </TabsContent>
      </Tabs>
    </div>
  );
}
