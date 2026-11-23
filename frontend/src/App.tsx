import React, { useState } from "react";
import { Navbar } from "./components/Navbar";
import { EnvironmentWizard } from "./components/EnvironmentWizard";
import { WorkflowCanvas } from "./components/WorkflowCanvas";
import { PluginsView } from "./components/PluginsView";
import { PluginManagerModal } from "./components/PluginManagerModal";
import { CitedReportViewer } from "./components/CitedReportViewer";
import { CaseManagerView } from "./components/CaseManagerView";
import { CaseVaultView } from "./components/CaseVaultView";
import { InvestigationView } from "./components/InvestigationView";
import { ForensicCopilotDrawer } from "./components/ForensicCopilotDrawer";
import { CitationDrawer } from "./components/CitationDrawer";
import { CustodyLedgerModal } from "./components/CustodyLedgerModal";
import { AuthGate } from "./components/AuthGate";
import { UserManagementModal } from "./components/UserManagementModal";
import { AuthProvider, useAuth } from "./context/AuthContext";
import { InvestigationProvider } from "./context/InvestigationContext";
import { useForensicStore } from "./store/useForensicStore";

function ForensicOpsShell() {
  const { user, isLoading } = useAuth();
  const { activeTab, setActiveTab } = useForensicStore();
  const [isPluginModalOpen, setIsPluginModalOpen] = useState<boolean>(false);
  const [isCustodyModalOpen, setIsCustodyModalOpen] = useState<boolean>(false);
  const [isUserModalOpen, setIsUserModalOpen] = useState<boolean>(false);
  const [isCopilotOpen, setIsCopilotOpen] = useState<boolean>(false);

  // If loading session state, display unobtrusive pulse loader
  if (isLoading) {
    return (
      <div className="min-h-screen bg-[#070a12] flex items-center justify-center text-cyan-400 font-mono text-xs">
        <div className="flex items-center space-x-2">
          <div className="w-2.5 h-2.5 bg-cyan-400 rounded-full animate-ping" />
          <span>Validating Investigator Session...</span>
        </div>
      </div>
    );
  }

  // If unauthenticated or no active user, present AuthGate
  if (!user) {
    return <AuthGate />;
  }

  return (
    <div className="min-h-screen bg-[#0b0f19] text-slate-200 flex flex-col font-sans select-none antialiased">
      {/* Top Fixed Navigation with RBAC Identity Bar */}
      <Navbar
        onOpenUserManagement={() => setIsUserModalOpen(true)}
        onToggleCopilot={() => setIsCopilotOpen((prev) => !prev)}
        isCopilotOpen={isCopilotOpen}
      />

      {/* Main Content Area */}
      <main className="flex-1 relative overflow-hidden">
        {activeTab === "wizard" && <EnvironmentWizard />}
        {activeTab === "cases" && <CaseManagerView />}
        {activeTab === "investigation" && <InvestigationView />}
        {activeTab === "canvas" && <WorkflowCanvas />}
        {activeTab === "plugins" && (
          <PluginsView onOpenOnboardModal={() => setIsPluginModalOpen(true)} />
        )}
        {activeTab === "report" && <CitedReportViewer />}
        {activeTab === "vault" && <CaseVaultView />}
        {activeTab === "custody" && <WorkflowCanvas />}
      </main>

      {/* Modals & Slide-out Drawers */}
      <PluginManagerModal
        isOpen={isPluginModalOpen}
        onClose={() => setIsPluginModalOpen(false)}
      />

      <UserManagementModal
        isOpen={isUserModalOpen}
        onClose={() => setIsUserModalOpen(false)}
      />

      <CustodyLedgerModal
        isOpen={isCustodyModalOpen || activeTab === "custody"}
        onClose={() => {
          setIsCustodyModalOpen(false);
          if (activeTab === "custody") {
            setActiveTab("canvas");
          }
        }}
      />

      <CitationDrawer />
      <ForensicCopilotDrawer
        isOpen={isCopilotOpen}
        onClose={() => setIsCopilotOpen(false)}
      />
    </div>
  );
}

export function App() {
  return (
    <AuthProvider>
      <InvestigationProvider>
        <ForensicOpsShell />
      </InvestigationProvider>
    </AuthProvider>
  );
}

export default App;
