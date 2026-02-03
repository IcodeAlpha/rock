export type Json =
  | string
  | number
  | boolean
  | null
  | { [key: string]: Json | undefined }
  | Json[]

export type Database = {
  // Allows to automatically instantiate createClient with right options
  // instead of createClient<Database, { PostgrestVersion: 'XX' }>(URL, KEY)
  __InternalSupabase: {
    PostgrestVersion: "14.1"
  }
  public: {
    Tables: {
      alerts: {
        Row: {
          acknowledged: boolean | null
          acknowledged_at: string | null
          acknowledged_by: string | null
          created_at: string
          description: string | null
          id: string
          organization_id: string | null
          severity: string
          source: string
          status: string
          title: string
          type: string | null
        }
        Insert: {
          acknowledged?: boolean | null
          acknowledged_at?: string | null
          acknowledged_by?: string | null
          created_at?: string
          description?: string | null
          id?: string
          organization_id?: string | null
          severity?: string
          source: string
          status?: string
          title: string
          type?: string | null
        }
        Update: {
          acknowledged?: boolean | null
          acknowledged_at?: string | null
          acknowledged_by?: string | null
          created_at?: string
          description?: string | null
          id?: string
          organization_id?: string | null
          severity?: string
          source?: string
          status?: string
          title?: string
          type?: string | null
        }
        Relationships: [
          {
            foreignKeyName: "alerts_organization_id_fkey"
            columns: ["organization_id"]
            isOneToOne: false
            referencedRelation: "organizations"
            referencedColumns: ["id"]
          },
        ]
      }
      incidents: {
        Row: {
          assigned_team: string | null
          assigned_to: string | null
          created_at: string
          description: string | null
          id: string
          incident_number: string
          organization_id: string | null
          prediction_id: string | null
          priority: string | null
          resolved_at: string | null
          response_level: number | null
          severity: string
          source: string | null
          status: string
          timeline: Json | null
          title: string
          updated_at: string
        }
        Insert: {
          assigned_team?: string | null
          assigned_to?: string | null
          created_at?: string
          description?: string | null
          id?: string
          incident_number: string
          organization_id?: string | null
          prediction_id?: string | null
          priority?: string | null
          resolved_at?: string | null
          response_level?: number | null
          severity?: string
          source?: string | null
          status?: string
          timeline?: Json | null
          title: string
          updated_at?: string
        }
        Update: {
          assigned_team?: string | null
          assigned_to?: string | null
          created_at?: string
          description?: string | null
          id?: string
          incident_number?: string
          organization_id?: string | null
          prediction_id?: string | null
          priority?: string | null
          resolved_at?: string | null
          response_level?: number | null
          severity?: string
          source?: string | null
          status?: string
          timeline?: Json | null
          title?: string
          updated_at?: string
        }
        Relationships: [
          {
            foreignKeyName: "incidents_organization_id_fkey"
            columns: ["organization_id"]
            isOneToOne: false
            referencedRelation: "organizations"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "incidents_prediction_id_fkey"
            columns: ["prediction_id"]
            isOneToOne: false
            referencedRelation: "predictions"
            referencedColumns: ["id"]
          },
        ]
      }
      invitations: {
        Row: {
          accepted_at: string | null
          created_at: string
          email: string
          expires_at: string
          id: string
          invited_by: string | null
          organization_id: string
          role: Database["public"]["Enums"]["app_role"]
          status: string
          token: string
        }
        Insert: {
          accepted_at?: string | null
          created_at?: string
          email: string
          expires_at?: string
          id?: string
          invited_by?: string | null
          organization_id: string
          role?: Database["public"]["Enums"]["app_role"]
          status?: string
          token?: string
        }
        Update: {
          accepted_at?: string | null
          created_at?: string
          email?: string
          expires_at?: string
          id?: string
          invited_by?: string | null
          organization_id?: string
          role?: Database["public"]["Enums"]["app_role"]
          status?: string
          token?: string
        }
        Relationships: [
          {
            foreignKeyName: "invitations_organization_id_fkey"
            columns: ["organization_id"]
            isOneToOne: false
            referencedRelation: "organizations"
            referencedColumns: ["id"]
          },
        ]
      }
      organization_members: {
        Row: {
          created_at: string
          id: string
          organization_id: string
          role: Database["public"]["Enums"]["app_role"]
          user_id: string
        }
        Insert: {
          created_at?: string
          id?: string
          organization_id: string
          role?: Database["public"]["Enums"]["app_role"]
          user_id: string
        }
        Update: {
          created_at?: string
          id?: string
          organization_id?: string
          role?: Database["public"]["Enums"]["app_role"]
          user_id?: string
        }
        Relationships: [
          {
            foreignKeyName: "organization_members_organization_id_fkey"
            columns: ["organization_id"]
            isOneToOne: false
            referencedRelation: "organizations"
            referencedColumns: ["id"]
          },
        ]
      }
      organization_profiles: {
        Row: {
          created_at: string
          critical_systems: string[] | null
          geographic_regions: string[] | null
          id: string
          industry: string
          name: string
          organization_id: string | null
          suppliers: string[] | null
          threat_actors: string[] | null
          updated_at: string
        }
        Insert: {
          created_at?: string
          critical_systems?: string[] | null
          geographic_regions?: string[] | null
          id?: string
          industry?: string
          name?: string
          organization_id?: string | null
          suppliers?: string[] | null
          threat_actors?: string[] | null
          updated_at?: string
        }
        Update: {
          created_at?: string
          critical_systems?: string[] | null
          geographic_regions?: string[] | null
          id?: string
          industry?: string
          name?: string
          organization_id?: string | null
          suppliers?: string[] | null
          threat_actors?: string[] | null
          updated_at?: string
        }
        Relationships: [
          {
            foreignKeyName: "organization_profiles_organization_id_fkey"
            columns: ["organization_id"]
            isOneToOne: false
            referencedRelation: "organizations"
            referencedColumns: ["id"]
          },
        ]
      }
      organizations: {
        Row: {
          created_at: string
          id: string
          industry: string | null
          name: string
          slug: string
          updated_at: string
        }
        Insert: {
          created_at?: string
          id?: string
          industry?: string | null
          name: string
          slug: string
          updated_at?: string
        }
        Update: {
          created_at?: string
          id?: string
          industry?: string | null
          name?: string
          slug?: string
          updated_at?: string
        }
        Relationships: []
      }
      osint_threats: {
        Row: {
          affected_industries: string[] | null
          affected_systems: string[] | null
          created_at: string
          description: string | null
          id: string
          indicators: string[] | null
          is_actionable: boolean | null
          organization_id: string | null
          raw_data: Json | null
          recommended_actions: string[] | null
          relevance_factors: string[] | null
          relevance_score: number | null
          severity: string
          source: string
          threat_type: string
          title: string
        }
        Insert: {
          affected_industries?: string[] | null
          affected_systems?: string[] | null
          created_at?: string
          description?: string | null
          id?: string
          indicators?: string[] | null
          is_actionable?: boolean | null
          organization_id?: string | null
          raw_data?: Json | null
          recommended_actions?: string[] | null
          relevance_factors?: string[] | null
          relevance_score?: number | null
          severity?: string
          source: string
          threat_type: string
          title: string
        }
        Update: {
          affected_industries?: string[] | null
          affected_systems?: string[] | null
          created_at?: string
          description?: string | null
          id?: string
          indicators?: string[] | null
          is_actionable?: boolean | null
          organization_id?: string | null
          raw_data?: Json | null
          recommended_actions?: string[] | null
          relevance_factors?: string[] | null
          relevance_score?: number | null
          severity?: string
          source?: string
          threat_type?: string
          title?: string
        }
        Relationships: [
          {
            foreignKeyName: "osint_threats_organization_id_fkey"
            columns: ["organization_id"]
            isOneToOne: false
            referencedRelation: "organizations"
            referencedColumns: ["id"]
          },
        ]
      }
      predictions: {
        Row: {
          affected_systems: string[] | null
          confidence: number
          converted_to_incident_id: string | null
          created_at: string
          description: string | null
          id: string
          impact: string | null
          organization_id: string | null
          probability: number
          severity: string
          source: string | null
          status: string
          timeframe: string | null
          title: string
          updated_at: string
        }
        Insert: {
          affected_systems?: string[] | null
          confidence?: number
          converted_to_incident_id?: string | null
          created_at?: string
          description?: string | null
          id?: string
          impact?: string | null
          organization_id?: string | null
          probability?: number
          severity?: string
          source?: string | null
          status?: string
          timeframe?: string | null
          title: string
          updated_at?: string
        }
        Update: {
          affected_systems?: string[] | null
          confidence?: number
          converted_to_incident_id?: string | null
          created_at?: string
          description?: string | null
          id?: string
          impact?: string | null
          organization_id?: string | null
          probability?: number
          severity?: string
          source?: string | null
          status?: string
          timeframe?: string | null
          title?: string
          updated_at?: string
        }
        Relationships: [
          {
            foreignKeyName: "fk_converted_incident"
            columns: ["converted_to_incident_id"]
            isOneToOne: false
            referencedRelation: "incidents"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "predictions_organization_id_fkey"
            columns: ["organization_id"]
            isOneToOne: false
            referencedRelation: "organizations"
            referencedColumns: ["id"]
          },
        ]
      }
      profiles: {
        Row: {
          avatar_url: string | null
          created_at: string
          email: string
          full_name: string | null
          id: string
          updated_at: string
        }
        Insert: {
          avatar_url?: string | null
          created_at?: string
          email: string
          full_name?: string | null
          id: string
          updated_at?: string
        }
        Update: {
          avatar_url?: string | null
          created_at?: string
          email?: string
          full_name?: string | null
          id?: string
          updated_at?: string
        }
        Relationships: []
      }
      reports: {
        Row: {
          content: string | null
          created_at: string
          file_url: string | null
          generated_by: string | null
          id: string
          organization_id: string | null
          period: string | null
          status: string
          summary: string | null
          title: string
          type: string
        }
        Insert: {
          content?: string | null
          created_at?: string
          file_url?: string | null
          generated_by?: string | null
          id?: string
          organization_id?: string | null
          period?: string | null
          status?: string
          summary?: string | null
          title: string
          type?: string
        }
        Update: {
          content?: string | null
          created_at?: string
          file_url?: string | null
          generated_by?: string | null
          id?: string
          organization_id?: string | null
          period?: string | null
          status?: string
          summary?: string | null
          title?: string
          type?: string
        }
        Relationships: [
          {
            foreignKeyName: "reports_organization_id_fkey"
            columns: ["organization_id"]
            isOneToOne: false
            referencedRelation: "organizations"
            referencedColumns: ["id"]
          },
        ]
      }
      scheduled_reports: {
        Row: {
          created_at: string
          enabled: boolean | null
          id: string
          last_run_at: string | null
          next_run_at: string | null
          organization_id: string | null
          recipients: string[] | null
          schedule: string
          title: string
          type: string
        }
        Insert: {
          created_at?: string
          enabled?: boolean | null
          id?: string
          last_run_at?: string | null
          next_run_at?: string | null
          organization_id?: string | null
          recipients?: string[] | null
          schedule: string
          title: string
          type?: string
        }
        Update: {
          created_at?: string
          enabled?: boolean | null
          id?: string
          last_run_at?: string | null
          next_run_at?: string | null
          organization_id?: string | null
          recipients?: string[] | null
          schedule?: string
          title?: string
          type?: string
        }
        Relationships: [
          {
            foreignKeyName: "scheduled_reports_organization_id_fkey"
            columns: ["organization_id"]
            isOneToOne: false
            referencedRelation: "organizations"
            referencedColumns: ["id"]
          },
        ]
      }
    }
    Views: {
      [_ in never]: never
    }
    Functions: {
      get_user_organization_id: { Args: { user_uuid: string }; Returns: string }
      has_org_access: {
        Args: { _org_id: string; _user_id: string }
        Returns: boolean
      }
      has_role: {
        Args: {
          _role: Database["public"]["Enums"]["app_role"]
          _user_id: string
        }
        Returns: boolean
      }
    }
    Enums: {
      app_role: "admin" | "analyst" | "viewer"
    }
    CompositeTypes: {
      [_ in never]: never
    }
  }
}

type DatabaseWithoutInternals = Omit<Database, "__InternalSupabase">

type DefaultSchema = DatabaseWithoutInternals[Extract<keyof Database, "public">]

export type Tables<
  DefaultSchemaTableNameOrOptions extends
    | keyof (DefaultSchema["Tables"] & DefaultSchema["Views"])
    | { schema: keyof DatabaseWithoutInternals },
  TableName extends DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof (DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"] &
        DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Views"])
    : never = never,
> = DefaultSchemaTableNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? (DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"] &
      DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Views"])[TableName] extends {
      Row: infer R
    }
    ? R
    : never
  : DefaultSchemaTableNameOrOptions extends keyof (DefaultSchema["Tables"] &
        DefaultSchema["Views"])
    ? (DefaultSchema["Tables"] &
        DefaultSchema["Views"])[DefaultSchemaTableNameOrOptions] extends {
        Row: infer R
      }
      ? R
      : never
    : never

export type TablesInsert<
  DefaultSchemaTableNameOrOptions extends
    | keyof DefaultSchema["Tables"]
    | { schema: keyof DatabaseWithoutInternals },
  TableName extends DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"]
    : never = never,
> = DefaultSchemaTableNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"][TableName] extends {
      Insert: infer I
    }
    ? I
    : never
  : DefaultSchemaTableNameOrOptions extends keyof DefaultSchema["Tables"]
    ? DefaultSchema["Tables"][DefaultSchemaTableNameOrOptions] extends {
        Insert: infer I
      }
      ? I
      : never
    : never

export type TablesUpdate<
  DefaultSchemaTableNameOrOptions extends
    | keyof DefaultSchema["Tables"]
    | { schema: keyof DatabaseWithoutInternals },
  TableName extends DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"]
    : never = never,
> = DefaultSchemaTableNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"][TableName] extends {
      Update: infer U
    }
    ? U
    : never
  : DefaultSchemaTableNameOrOptions extends keyof DefaultSchema["Tables"]
    ? DefaultSchema["Tables"][DefaultSchemaTableNameOrOptions] extends {
        Update: infer U
      }
      ? U
      : never
    : never

export type Enums<
  DefaultSchemaEnumNameOrOptions extends
    | keyof DefaultSchema["Enums"]
    | { schema: keyof DatabaseWithoutInternals },
  EnumName extends DefaultSchemaEnumNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaEnumNameOrOptions["schema"]]["Enums"]
    : never = never,
> = DefaultSchemaEnumNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[DefaultSchemaEnumNameOrOptions["schema"]]["Enums"][EnumName]
  : DefaultSchemaEnumNameOrOptions extends keyof DefaultSchema["Enums"]
    ? DefaultSchema["Enums"][DefaultSchemaEnumNameOrOptions]
    : never

export type CompositeTypes<
  PublicCompositeTypeNameOrOptions extends
    | keyof DefaultSchema["CompositeTypes"]
    | { schema: keyof DatabaseWithoutInternals },
  CompositeTypeName extends PublicCompositeTypeNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[PublicCompositeTypeNameOrOptions["schema"]]["CompositeTypes"]
    : never = never,
> = PublicCompositeTypeNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[PublicCompositeTypeNameOrOptions["schema"]]["CompositeTypes"][CompositeTypeName]
  : PublicCompositeTypeNameOrOptions extends keyof DefaultSchema["CompositeTypes"]
    ? DefaultSchema["CompositeTypes"][PublicCompositeTypeNameOrOptions]
    : never

export const Constants = {
  public: {
    Enums: {
      app_role: ["admin", "analyst", "viewer"],
    },
  },
} as const
