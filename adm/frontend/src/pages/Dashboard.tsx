import { useCallback, useEffect, useState } from "react";
import {
  Box, Button, Grid2 as Grid, Typography, CircularProgress, Tabs, Tab,
  Dialog, DialogTitle, DialogContent, DialogActions, Alert,
} from "@mui/material";
import AddIcon from "@mui/icons-material/Add";
import RefreshIcon from "@mui/icons-material/Refresh";
import { useTranslation } from "react-i18next";
import api from "../api/client";
import type { AdminRole, Server, SourceRevision, VpnServer } from "../api/types";
import ServerCard from "../components/ServerCard";
import ProvisionDialog from "../components/ProvisionDialog";
import ServerDetailDialog from "../components/ServerDetailDialog";
import VpnServerCard from "../components/VpnServerCard";
import AddVpnServerDialog from "../components/AddVpnServerDialog";
import SetupVpnServerDialog from "../components/SetupVpnServerDialog";
import ServiceInventoryDialog from "../components/ServiceInventoryDialog";
import VpnServerDetailDialog from "../components/VpnServerDetailDialog";
import EditServerDialog from "../components/EditServerDialog";
import MonitoringTab from "../components/MonitoringTab";
import VpnUsersTab from "../components/VpnUsersTab";
import PoolsTab from "../components/PoolsTab";
import OutputViewer from "../components/OutputViewer";

export default function Dashboard({ role }: { role: AdminRole }) {
  const { t } = useTranslation();
  // A scoped admin has nothing to do on the other tabs — the API refuses
  // them anyway, so showing them would only produce dead controls.
  const isSuperadmin = role === "superadmin";
  const [tab, setTab] = useState(() => {
    if (role !== "superadmin") return 2;  // Users is all they can reach
    const saved = localStorage.getItem("adm_dashboard_tab");
    return saved ? parseInt(saved) : 0;
  });

  // Exit servers state
  const [servers, setServers] = useState<Server[]>([]);
  const [serversLoading, setServersLoading] = useState(true);
  const [provisionOpen, setProvisionOpen] = useState(false);
  const [selectedId, setSelectedId] = useState<number | null>(null);

  // VPN servers state
  const [vpnServers, setVpnServers] = useState<VpnServer[]>([]);
  const [vpnLoading, setVpnLoading] = useState(true);
  const [addVpnOpen, setAddVpnOpen] = useState(false);
  const [setupVpnOpen, setSetupVpnOpen] = useState(false);
  const [servicesFor, setServicesFor] = useState<VpnServer | null>(null);
  const [sourceRevision, setSourceRevision] = useState<SourceRevision | null>(null);
  const [selectedVpn, setSelectedVpn] = useState<VpnServer | null>(null);
  const [editingExit, setEditingExit] = useState<Server | null>(null);
  const [editingVpn, setEditingVpn] = useState<VpnServer | null>(null);
  const [updatingVpn, setUpdatingVpn] = useState<VpnServer | null>(null);
  const [updateOpId, setUpdateOpId] = useState<number | null>(null);
  const [updateOp, setUpdateOp] = useState<{ status: string; output?: string } | null>(null);
  const [updateError, setUpdateError] = useState("");
  // Covers the POST and the gap before the first poll, not only "running".
  const updateBusy = updatingVpn !== null && !updateError
    && (updateOp === null || updateOp.status === "running");

  const fetchServers = useCallback(async () => {
    try {
      const { data } = await api.get("/servers");
      if (data.ok) setServers(data.data);
    } catch { /* handled by interceptor */ }
    setServersLoading(false);
  }, []);

  const fetchVpnServers = useCallback(async () => {
    try {
      const { data } = await api.get("/vpn-servers");
      if (data.ok) setVpnServers(data.data);
      // What ADM would deploy now — each card compares itself against it.
      if (isSuperadmin) {
        const rev = await api.get("/vpn-servers/source-revision");
        if (rev.data.ok) setSourceRevision(rev.data.data);
      }
    } catch { /* handled by interceptor */ }
    setVpnLoading(false);
  }, [isSuperadmin]);

  // Deploy the current source onto a server the badge says is behind. The
  // endpoint has existed all along; nothing in the UI called it, so "update
  // available" was a statement with no matching action and sites stayed behind.
  const startVpnUpdate = useCallback(async (server: VpnServer) => {
    setUpdatingVpn(server);
    setUpdateOp(null);
    setUpdateOpId(null);
    setUpdateError("");
    try {
      const { data } = await api.post(`/vpn-servers/${server.id}/update`, {});
      if (data.ok && Number.isInteger(data.data?.operation_id) && data.data.operation_id > 0) setUpdateOpId(data.data.operation_id);
      else setUpdateError(data.error || t("common.error"));
    } catch (err: unknown) {
      const msg = (err as { response?: { data?: { error?: string } } })
        ?.response?.data?.error;
      setUpdateError(msg || t("common.error"));
    }
  }, [t]);

  // Poll until the deploy stops running, then re-read the servers so the badge
  // shows what actually landed rather than what was asked for.
  useEffect(() => {
    if (!updateOpId) return;
    const interval = setInterval(async () => {
      try {
        const { data } = await api.get(`/operations/${updateOpId}`);
        if (data.ok) {
          setUpdateOp(data.data);
          if (data.data.status !== "running") {
            clearInterval(interval);
            fetchVpnServers();
          }
        }
      } catch { /* ignore */ }
    }, 2000);
    return () => clearInterval(interval);
  }, [updateOpId, fetchVpnServers]);

  // Fetch exit servers on mount + polling
  useEffect(() => {
    fetchServers();
    const interval = setInterval(fetchServers, 30000);
    return () => clearInterval(interval);
  }, [fetchServers]);

  // Fetch VPN servers when tab 1 is active
  useEffect(() => {
    if (tab === 1) {
      fetchVpnServers();
      const interval = setInterval(fetchVpnServers, 30000);
      return () => clearInterval(interval);
    }
  }, [tab, fetchVpnServers]);

  const handleTabChange = (_: unknown, newValue: number) => {
    setTab(newValue);
    localStorage.setItem("adm_dashboard_tab", String(newValue));
  };

  return (
    <Box sx={{ minWidth: 0 }}>
      <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 2, flexWrap: "wrap", gap: 2, p: { xs: 2, sm: 2.5 }, bgcolor: "background.paper", border: 1, borderColor: "divider", borderRadius: 2 }}>
        <Typography variant="h5" fontWeight={700} sx={{ letterSpacing: "-0.02em" }}>
          {t("dashboard.title")}
        </Typography>
        <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1, width: { xs: "100%", sm: "auto" }, "& > .MuiButton-root": { width: { xs: "100%", sm: "auto" }, minHeight: 36 } }}>
          {/* Only the server tabs use this toolbar; Users and Monitoring
              bring their own. */}
          {isSuperadmin && tab < 2 && (
            <Button
              startIcon={<RefreshIcon />}
              onClick={() => {
                if (tab === 0) { setServersLoading(true); fetchServers(); }
                else { setVpnLoading(true); fetchVpnServers(); }
              }}
              variant="outlined"
              size="small"
            >
              {t("dashboard.refresh")}
            </Button>
          )}
          {tab === 0 && (
            <Button
              startIcon={<AddIcon />}
              onClick={() => setProvisionOpen(true)}
              variant="contained"
              size="small"
            >
              {t("dashboard.addServer")}
            </Button>
          )}
          {tab === 1 && (
            <>
              <Button
                startIcon={<AddIcon />}
                onClick={() => setSetupVpnOpen(true)}
                variant="contained"
                size="small"
              >
                {t("dashboard.setupVpnServer")}
              </Button>
              <Button
                startIcon={<AddIcon />}
                onClick={() => setAddVpnOpen(true)}
                variant="outlined"
                size="small"
              >
                {t("dashboard.addVpnServer")}
              </Button>
            </>
          )}
        </Box>
      </Box>

      <Tabs
        value={tab}
        onChange={handleTabChange}
        variant="scrollable"
        scrollButtons="auto"
        sx={{ mb: 3, borderBottom: 1, borderColor: "divider", "& .MuiTab-root": { minHeight: 52, px: { xs: 2, sm: 3 }, fontWeight: 600 }, "& .MuiTabs-indicator": { height: 3, borderRadius: "3px 3px 0 0" } }}
      >
        <Tab label={t("dashboard.tabExitServers")} sx={{ display: isSuperadmin ? undefined : "none" }} />
        <Tab label={t("dashboard.tabVpnServers")} sx={{ display: isSuperadmin ? undefined : "none" }} />
        <Tab label={t("dashboard.tabUsers")} />
        <Tab label={t("dashboard.tabMonitoring")} sx={{ display: isSuperadmin ? undefined : "none" }} />
        <Tab label={t("pools.title")} sx={{ display: isSuperadmin ? undefined : "none" }} />
      </Tabs>

      {/* ── Tab 0: Exit Servers ──────────────────── */}
      {tab === 0 && (
        <>
          {serversLoading && servers.length === 0 ? (
            <Box sx={{ display: "flex", justifyContent: "center", py: 8 }}>
              <CircularProgress />
            </Box>
          ) : servers.length === 0 ? (
            <Typography color="text.secondary" sx={{ py: 8, textAlign: "center" }}>
              {t("dashboard.noServers")}
            </Typography>
          ) : (
            <Grid container spacing={2}>
              {servers.map((server) => (
                <Grid key={server.id} size={{ xs: 12, sm: 6, md: 4 }} sx={{ display: "flex", minWidth: 0 }}>
                  <ServerCard
                    server={server}
                    onClick={() => setSelectedId(server.id)}
                    onEdit={() => setEditingExit(server)}
                  />
                </Grid>
              ))}
            </Grid>
          )}

          <EditServerDialog
            open={!!editingExit}
            kind="exit"
            server={editingExit}
            onClose={() => setEditingExit(null)}
            onSaved={() => { setEditingExit(null); fetchServers(); }}
          />

          <ProvisionDialog
            open={provisionOpen}
            onClose={() => setProvisionOpen(false)}
            onCreated={() => { setProvisionOpen(false); fetchServers(); }}
          />

          {selectedId && (
            <ServerDetailDialog
              serverId={selectedId}
              open={true}
              onClose={() => setSelectedId(null)}
              onRefresh={fetchServers}
            />
          )}
        </>
      )}

      {/* ── Tab 1: VPN Servers ───────────────────── */}
      {tab === 1 && (
        <>
          {vpnLoading && vpnServers.length === 0 ? (
            <Box sx={{ display: "flex", justifyContent: "center", py: 8 }}>
              <CircularProgress />
            </Box>
          ) : vpnServers.length === 0 ? (
            <Typography color="text.secondary" sx={{ py: 8, textAlign: "center" }}>
              {t("dashboard.noVpnServers")}
            </Typography>
          ) : (
            <Grid container spacing={2}>
              {vpnServers.map((server) => (
                <Grid key={server.id} size={{ xs: 12, sm: 6, md: 4 }} sx={{ display: "flex", minWidth: 0 }}>
                  <VpnServerCard
                    server={server}
                    sourceRevision={sourceRevision}
                    onClick={() => setSelectedVpn(server)}
                    onEdit={() => setEditingVpn(server)}
                    onServices={() => setServicesFor(server)}
                    onDelete={() => setSelectedVpn(server)}
                    onUpdate={isSuperadmin ? () => startVpnUpdate(server) : undefined}
                  />
                </Grid>
              ))}
            </Grid>
          )}

          <Dialog
            open={!!updatingVpn}
            onClose={() => {
              // Closing mid-deploy would only hide it: the operation keeps
              // running on the server either way, so say so rather than
              // pretending the dialog is the deploy.
              if (updateBusy) return;
              setUpdatingVpn(null);
              setUpdateOpId(null);
              setUpdateOp(null);
              setUpdateError("");
            }}
            fullWidth
            maxWidth="md"
          >
            <DialogTitle sx={{ overflowWrap: "anywhere" }}>
              {t("vpnServer.updateTitle", { name: updatingVpn?.display_name ?? "" })}
            </DialogTitle>
            <DialogContent>
              {updateError && <Alert severity="error" sx={{ mb: 2, overflowWrap: "anywhere", "& .MuiAlert-message": { minWidth: 0 } }}>{updateError}</Alert>}
              {!updateError && !updateOp && (
                <Box sx={{ display: "flex", alignItems: "center", gap: 1, py: 2 }}>
                  <CircularProgress size={18} />
                  <Typography variant="body2">{t("vpnServer.updateStarting")}</Typography>
                </Box>
              )}
              {updateOp && (
                <OutputViewer output={updateOp.output || ""} status={updateOp.status} />
              )}
            </DialogContent>
            <DialogActions sx={{ p: 2, gap: 1, flexWrap: "wrap", "& .MuiButton-root": { minHeight: 40 } }}>
              <Button
                disabled={updateBusy}
                onClick={() => {
                  setUpdatingVpn(null);
                  setUpdateOpId(null);
                  setUpdateOp(null);
                  setUpdateError("");
                }}
              >
                {t("common.close")}
              </Button>
            </DialogActions>
          </Dialog>

          <ServiceInventoryDialog
        open={!!servicesFor}
        serverId={servicesFor?.id ?? null}
        serverName={servicesFor?.display_name ?? ""}
        onClose={() => setServicesFor(null)}
      />

      <SetupVpnServerDialog
            open={setupVpnOpen}
            onClose={() => setSetupVpnOpen(false)}
            onCreated={() => { setSetupVpnOpen(false); fetchVpnServers(); }}
          />

          <EditServerDialog
            open={!!editingVpn}
            kind="vpn"
            server={editingVpn}
            onClose={() => setEditingVpn(null)}
            onSaved={() => { setEditingVpn(null); fetchVpnServers(); }}
          />

          <AddVpnServerDialog
            open={addVpnOpen}
            onClose={() => setAddVpnOpen(false)}
            onCreated={() => { setAddVpnOpen(false); fetchVpnServers(); }}
          />

          {selectedVpn && (
            <VpnServerDetailDialog
              vpnServer={selectedVpn}
              open={true}
              onClose={() => setSelectedVpn(null)}
              onRefresh={fetchVpnServers}
              onDeleted={() => { setSelectedVpn(null); fetchVpnServers(); }}
            />
          )}
        </>
      )}

      {/* ── Tab 2: Monitoring ──────────────────────── */}
      {tab === 2 && <VpnUsersTab isSuperadmin={isSuperadmin} />}
      {tab === 3 && <MonitoringTab />}
      {tab === 4 && isSuperadmin && <PoolsTab />}
    </Box>
  );
}
