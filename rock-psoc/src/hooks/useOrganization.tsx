import { createContext, useContext, ReactNode } from 'react';
import { useAuth } from './useAuth';

interface OrganizationContextType {
  organizationId: string | null;
  userRole: 'admin' | 'analyst' | 'viewer' | null;
  canCreate: boolean;
  canEdit: boolean;
  canDelete: boolean;
  isAdmin: boolean;
  isAnalyst: boolean;
  isViewer: boolean;
}

const OrganizationContext = createContext<OrganizationContextType | undefined>(undefined);

export const OrganizationProvider = ({ children }: { children: ReactNode }) => {
  const { organizationId, userRole } = useAuth();

  const isAdmin = userRole === 'admin';
  const isAnalyst = userRole === 'analyst';
  const isViewer = userRole === 'viewer';

  // Permission helpers
  const canCreate = isAdmin || isAnalyst;
  const canEdit = isAdmin || isAnalyst;
  const canDelete = isAdmin;

  return (
    <OrganizationContext.Provider value={{
      organizationId,
      userRole,
      canCreate,
      canEdit,
      canDelete,
      isAdmin,
      isAnalyst,
      isViewer
    }}>
      {children}
    </OrganizationContext.Provider>
  );
};

export const useOrganization = () => {
  const context = useContext(OrganizationContext);
  if (context === undefined) {
    throw new Error('useOrganization must be used within an OrganizationProvider');
  }
  return context;
};
