import { Toaster } from '@/components/ui/toaster'
import { Toaster as Sonner } from '@/components/ui/sonner'
import { TooltipProvider } from '@/components/ui/tooltip'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { BrowserRouter, Routes, Route } from 'react-router-dom'
import { AuthProvider } from '@/hooks/useAuth'
import { OrganizationProvider } from '@/hooks/useOrganization'
import { ProtectedRoute } from '@/components/auth/ProtectedRoute'
import Landing from '@/pages/Landing'
import Auth from '@/pages/Auth'
import Index from '@/pages/Index'
import NotFound from '@/pages/NotFound'
import Privacy from '@/pages/Privacy';
import Terms from '@/pages/Terms'; 
import { AcceptInvitePage } from '@/pages/AcceptInvitePage';

const queryClient = new QueryClient()

const App = () => (
  <QueryClientProvider client={queryClient}>
    <TooltipProvider>
      <Toaster />
      <Sonner />
      <BrowserRouter>
        <AuthProvider>
          <OrganizationProvider>
            <Routes>
              {/* Public landing page - route: / */}
              <Route path="/" element={<Landing />} />

              {/* Public auth page - route: /auth */}
              <Route path="/auth" element={<Auth />} />

              <Route path="/accept-invite" element={<AcceptInvitePage />} />

               <Route path="/privacy" element={<Privacy />} />  {/* NEW */}
              <Route path="/terms" element={<Terms />} />      {/* NEW */}

              {/* Protected app route - route: /app */}
              <Route
                path="/app"
                element={
                  <ProtectedRoute>
                    <Index />
                  </ProtectedRoute>
                }
              />

              {/* Catch all 404 - route: /* */}
              <Route path="*" element={<NotFound />} />
            </Routes>
          </OrganizationProvider>
        </AuthProvider>
      </BrowserRouter>
    </TooltipProvider>
  </QueryClientProvider>
)

export default App