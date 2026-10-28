import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Alert, Box, Button, Checkbox, Chip, CircularProgress, IconButton, ListItemIcon,
  ListItemText, MenuItem, Paper, Select, Snackbar, Table, TableBody, TableCell,
  TableContainer, TableHead, TableRow, TableSortLabel, TextField, Tooltip,
  Typography,
} from "@mui/material";
import AddIcon from "@mui/icons-material/Add";
import RefreshIcon from "@mui/icons-material/Refresh";
import SyncIcon from "@mui/icons-material/Sync";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import RadioButtonUncheckedIcon from "@mui/icons-material/RadioButtonUnchecked";
import LanIcon from "@mui/icons-material/Lan";
import BlockIcon from "@mui/icons-material/Block";
import AltRouteIcon from "@mui/icons-material/AltRoute";
import ScienceIcon from "@mui/icons-material/Science";
import ClearIcon from "@mui/icons-material/Clear";
import { useTranslation } from "react-i18next";
import api from "../api/client";
import type {
  ServerProfile, ServerProfiles, SyncSummary, VpnServer, VpnUser, VpnUserAccess,
} from "../api/types";
import VpnUserDialog from "./VpnUserDialog";
import ConfirmRevokeDialog from "./ConfirmRevokeDialog";

function cellOf(user: VpnUser, serverId: number): VpnUserAccess | undefined {
  return user.servers.find((s) => s.vpn_server_id === serverId);
}

/** Rank a cell so sorting reads top-to-bottom as "most access first". */
function cellRank(cell: VpnUserAccess | undefined): number {
  if (!cell) return 0;
  return 1 + (cell.lan_access ? 1 : 0) + (cell.allowed_profiles?.length ? 1 : 0)
    + (cell.allow_smart_test ? 1 : 0);
}

type SortKey = string; // "username" | "enabled" | `server:${id}`
type ServerFilter = "granted" | "not" | "lan_on" | "lan_off" | "route_on" | "route_off" | "pending";

const SERVER_FILTERS: ServerFilter[] = ["granted", "not", "lan_on", "lan_off", "route_on", "route_off", "pending"];

const FILTER_LABEL: Record<ServerFilter, string> = {
  granted: "vpnUsers.filterGranted",
  not: "vpnUsers.filterNotGranted",
  lan_on: "vpnUsers.filterLanOn",
  lan_off: "vpnUsers.filterLanOff",
  route_on: "vpnUsers.filterRouteOn",
  route_off: "vpnUsers.filterRouteOff",
  pending: "vpnUsers.filterPending",
};

/** The same glyphs the cells use, so a filter reads as "rows that look like this". */
function FilterIcon({ kind }: { kind: ServerFilter }) {
  const sx = { fontSize: 18 };
  switch (kind) {
    case "granted": return <CheckCircleIcon sx={sx} color="success" />;
    case "not": return <RadioButtonUncheckedIcon sx={{ ...sx, color: "action.disabled" }} />;
    case "lan_on": return <LanIcon sx={sx} color="primary" />;
    case "lan_off": return <BlockIcon sx={sx} color="error" />;
    case "route_on": return <AltRouteIcon sx={sx} color="info" />;
    case "route_off": return <AltRouteIcon sx={{ ...sx, color: "action.disabled" }} />;
    case "pending": return <CheckCircleIcon sx={sx} color="warning" />;
  }
}

/**
 * Does a cell match one option? Selections within a column are OR-ed, which
 * is what makes a combination like "not authorized" + "LAN blocked" useful:
 * everyone who cannot reach that site's LAN, whichever way.
 */
function matchesFilter(cell: VpnUserAccess | undefined, f: ServerFilter): boolean {
  switch (f) {
    case "granted": return Boolean(cell);
    case "not": return !cell;
    case "lan_on": return Boolean(cell && cell.lan_access);
    case "lan_off": return Boolean(cell && !cell.lan_access);
    case "route_on": return Boolean(cell && cell.allowed_profiles?.length);
    case "route_off": return Boolean(cell && !cell.allowed_profiles?.length);
    case "pending": return Boolean(cell && cell.sync_status !== "synced");
  }
}

/**
 * A filter control with its own reset.
 *
 * The button sits beside the control rather than inside the dropdown: a
 * valueless MenuItem inside a multiple Select races MUI's change handler.
 * It keeps its space when inactive so column widths do not jump.
 */
function FilterCell({ active, onClear, title, children }: {
  active: boolean;
  onClear: () => void;
  title: string;
  children: React.ReactNode;
}) {
  return (
    <Box sx={{ display: "flex", alignItems: "center", gap: 0.25 }}>
      <Box sx={{ flexGrow: 1, minWidth: 0 }}>{children}</Box>
      <Tooltip title={title}>
        <IconButton
          size="small"
          onClick={onClear}
          tabIndex={active ? 0 : -1}
          aria-hidden={!active}
          sx={{ visibility: active ? "visible" : "hidden", p: 0.25 }}
        >
          <ClearIcon sx={{ fontSize: 16 }} />
        </IconButton>
      </Tooltip>
    </Box>
  );
}

type SyncResult = {
  failed?: { target: string; error: string }[];
  deferred?: { target: string; server: string; error: string }[];
  unreachable_servers?: string[];
};

export default function VpnUsersTab({ isSuperadmin }: { isSuperadmin: boolean }) {
  const { t } = useTranslation();
  const [users, setUsers] = useState<VpnUser[]>([]);
  const [servers, setServers] = useState<VpnServer[]>([]);
  const [summary, setSummary] = useState<SyncSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState<string | null>(null);
  const channelRequests = useRef(new Set<number>());
  const [savingChannels, setSavingChannels] = useState(new Set<number>());
  const [dialogUser, setDialogUser] = useState<VpnUser | null | "new">(null);
  const [revoking, setRevoking] = useState<{ user: VpnUser; server: VpnServer } | null>(null);
  const [snack, setSnack] = useState<{ msg: string; error?: boolean; warn?: boolean } | null>(null);

  // Column state
  const [sortKey, setSortKey] = useState<SortKey>("username");
  const [sortDir, setSortDir] = useState<"asc" | "desc">("asc");
  const [fUser, setFUser] = useState("");
  const [fEnabled, setFEnabled] = useState<"" | "on" | "off">("");
  const [fServer, setFServer] = useState<Record<number, ServerFilter[]>>({});

  const fetchAll = useCallback(async () => {
    try {
      const [u, s] = await Promise.all([
        api.get("/vpn-users"),
        api.get("/vpn-servers"),
      ]);
      if (u.data.ok) setUsers(u.data.data);
      if (s.data.ok) setServers(s.data.data);
      // Estate-wide sync state belongs to whoever manages the estate.
      if (isSuperadmin) {
        const sum = await api.get("/vpn-users/sync/status");
        if (sum.data.ok) setSummary(sum.data.data);
      }
    } catch { /* handled by interceptor */ }
    setLoading(false);
  }, [isSuperadmin]);

  useEffect(() => { fetchAll(); }, [fetchAll]);

  const toggleSort = (key: SortKey) => {
    if (sortKey === key) setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    else { setSortKey(key); setSortDir("asc"); }
  };

  const visible = useMemo(() => {
    const q = fUser.trim().toLowerCase();

    const rows = users.filter((u) => {
      if (q && !u.username.toLowerCase().includes(q) && !u.full_name.toLowerCase().includes(q)) {
        return false;
      }
      if (fEnabled === "on" && !u.enabled) return false;
      if (fEnabled === "off" && u.enabled) return false;

      // Within a column: OR. Across columns: AND.
      for (const s of servers) {
        const picked = fServer[s.id];
        if (!picked?.length) continue;
        const cell = cellOf(u, s.id);
        if (!picked.some((f) => matchesFilter(cell, f))) return false;
      }
      return true;
    });

    const dir = sortDir === "asc" ? 1 : -1;
    return [...rows].sort((a, b) => {
      if (sortKey === "enabled") {
        return (Number(a.enabled) - Number(b.enabled)) * dir
          || a.username.localeCompare(b.username);
      }
      if (sortKey.startsWith("server:")) {
        const id = Number(sortKey.slice(7));
        return (cellRank(cellOf(a, id)) - cellRank(cellOf(b, id))) * dir
          || a.username.localeCompare(b.username);
      }
      return a.username.localeCompare(b.username) * dir;
    });
  }, [users, servers, fUser, fEnabled, fServer, sortKey, sortDir]);

  /** A site that is switched off is not a failure: its changes stay queued
   *  and ADM delivers them when it answers again. Say so, in a different
   *  colour, instead of reporting the whole push as failed. */
  const waitingSnack = (sync?: SyncResult) => ({
    msg: t("vpnUsers.syncWaiting", {
      n: (sync?.deferred ?? []).length,
      servers: (sync?.unreachable_servers ?? []).join(", "),
    }),
    warn: true,
  });

  const reportSync = (sync?: SyncResult) => {
    const failed = sync?.failed ?? [];
    if (failed.length) {
      setSnack({
        msg: t("vpnUsers.syncFailed", {
          detail: failed.map((f) => `${f.target}: ${f.error}`).join(", "),
        }),
        error: true,
      });
    } else if ((sync?.deferred ?? []).length) {
      setSnack(waitingSnack(sync));
    }
  };

  /** Published Direct routes per server id, from ADM's poller cache — the
   *  same source the user dialog reads, so the matrix and the dialog cannot
   *  disagree about what a site offers. Cached server-side, so an unreachable
   *  site still shows its routes rather than appearing to have none. */
  const [serverProfiles, setServerProfiles] = useState<Record<string, ServerProfile[]>>({});

  useEffect(() => {
    let cancelled = false;
    api.get("/vpn-servers/profiles")
      .then(({ data }) => {
        if (cancelled || !data.ok) return;
        const entries = Object.entries(data.data as Record<string, ServerProfiles>);
        setServerProfiles(Object.fromEntries(
          entries.map(([id, entry]) => [id, entry.profiles ?? []]),
        ));
      })
      .catch(() => { /* the matrix still works without them */ });
    return () => { cancelled = true; };
  }, []);

  const grant = async (user: VpnUser, server: VpnServer, patch: Record<string, unknown>) => {
    const key = `${user.id}:${server.id}`;
    setBusy(key);
    try {
      const { data } = await api.put(`/vpn-users/${user.id}/access/${server.id}`, patch);
      if (data.ok) reportSync(data.data?.sync);
      else setSnack({ msg: data.error, error: true });
    } catch {
      setSnack({ msg: t("vpnUsers.requestFailed"), error: true });
    }
    setBusy(null);
    fetchAll();
  };

  const changeChannel = async (user: VpnUser, channel: VpnUser["update_channel"]) => {
    if (channel === user.update_channel || channelRequests.current.has(user.id)) return;
    channelRequests.current.add(user.id);
    setSavingChannels(new Set(channelRequests.current));
    try {
      const { data } = await api.put(`/vpn-users/${user.id}`, { update_channel: channel });
      if (!data.ok) {
        setSnack({ msg: data.error || t("vpnUsers.requestFailed"), error: true });
        return;
      }
      setUsers((current) => current.map((u) => u.id === user.id ? data.data : u));
      reportSync(data.data?.sync);
      await fetchAll();
    } catch (err: unknown) {
      const message = (err as { response?: { data?: { error?: string } } })?.response?.data?.error;
      setSnack({ msg: message || t("vpnUsers.requestFailed"), error: true });
    } finally {
      channelRequests.current.delete(user.id);
      setSavingChannels(new Set(channelRequests.current));
    }
  };

  const confirmRevoke = async () => {
    if (!revoking) return;
    const { user, server } = revoking;
    setRevoking(null);
    setBusy(`${user.id}:${server.id}`);
    try {
      const { data } = await api.delete(`/vpn-users/${user.id}/access/${server.id}`);
      if (data.ok) {
        reportSync(data.data?.sync);
        if (data.data?.pending_sync) setSnack({ msg: t("vpnUsers.revokeQueued") });
      } else setSnack({ msg: data.error, error: true });
    } catch {
      setSnack({ msg: t("vpnUsers.requestFailed"), error: true });
    }
    setBusy(null);
    fetchAll();
  };

  const syncAll = async () => {
    setBusy("sync");
    try {
      const { data } = await api.post("/vpn-users/sync", {});
      if (data.ok) {
        const failed = data.data.failed ?? [];
        const waiting = data.data.deferred ?? [];
        setSnack(failed.length
          ? { msg: t("vpnUsers.syncFailed", { detail: `${failed.length}` }), error: true }
          : waiting.length
            ? waitingSnack(data.data)
            : { msg: t("vpnUsers.syncDone") });
      }
    } catch {
      setSnack({ msg: t("vpnUsers.requestFailed"), error: true });
    }
    setBusy(null);
    fetchAll();
  };

  if (loading) {
    return <Box sx={{ display: "flex", justifyContent: "center", p: 4 }}><CircularProgress size={28} /></Box>;
  }

  const waiting = (summary?.pending ?? 0) + (summary?.pending_delete ?? 0);
  const filtersOn = Boolean(fUser) || Boolean(fEnabled)
    || Object.values(fServer).some((v) => v.length > 0);
  const selectSx = { minWidth: 120, "& .MuiSelect-select": { py: 0.5, fontSize: 13 } };

  return (
    <Box sx={{ minWidth: 0 }}>
      <Box sx={{ display: "flex", gap: 1, alignItems: "center", flexWrap: "wrap", mb: 2, pb: 2, borderBottom: 1, borderColor: "divider", "& .MuiButton-root": { minHeight: 40 } }}>
        <Typography variant="body2" color="text.secondary">
          {filtersOn
            ? t("vpnUsers.countFiltered", { shown: visible.length, total: users.length })
            : t("vpnUsers.count", { count: users.length })}
        </Typography>
        {filtersOn && (
          <Button size="small" onClick={() => { setFUser(""); setFEnabled(""); setFServer({}); }}>
            {t("vpnUsers.clearFilters")}
          </Button>
        )}
        <Box sx={{ flexGrow: 1 }} />
        {summary && (
          <Chip size="small" color={summary.synced ? "success" : "default"} variant="outlined"
            label={t("vpnUsers.syncedAssignments", { count: summary.synced })} />
        )}
        {waiting > 0 && (
          <Chip size="small" color="warning" label={t("vpnUsers.waiting", { count: waiting })} />
        )}
        {(summary?.error ?? 0) > 0 && (
          <Chip size="small" color="error" label={t("vpnUsers.failed", { count: summary!.error })} />
        )}
        {isSuperadmin && (
          <Tooltip title={t("vpnUsers.syncNow")}>
            <span>
              <IconButton onClick={syncAll} disabled={busy === "sync"}><SyncIcon /></IconButton>
            </span>
          </Tooltip>
        )}
        <Tooltip title={t("dashboard.refresh")}>
          <IconButton onClick={fetchAll}><RefreshIcon /></IconButton>
        </Tooltip>
        <Button variant="contained" startIcon={<AddIcon />} onClick={() => setDialogUser("new")}>
          {t("vpnUsers.addUser")}
        </Button>
      </Box>

      {summary?.deferred?.length ? (
        <Alert severity="warning" sx={{ mb: 2, "& .MuiAlert-message": { minWidth: 0, overflowWrap: "anywhere" } }}>
          {t("vpnUsers.offlineSitesWaiting", {
            servers: [...new Set(summary.deferred.map((e) => e.server_name))].join(", "),
          })}
        </Alert>
      ) : null}

      {summary?.errors?.length ? (
        <Alert severity="error" sx={{ mb: 2, "& .MuiAlert-message": { minWidth: 0, overflowWrap: "anywhere" } }}>
          {summary.errors.map((e) => `${e.username}@${e.server_name}: ${e.sync_error}`).join(" · ")}
        </Alert>
      ) : null}

      {servers.length === 0 ? (
        <Typography color="text.secondary">{t("dashboard.noVpnServers")}</Typography>
      ) : (
        <TableContainer component={Paper} sx={{ overflowX: "auto", border: 1, borderColor: "divider", scrollPaddingLeft: 300 }}>
          <Table
            size="small"
            stickyHeader
            sx={{
              minWidth: 460 + servers.length * 220,
              "& th:first-of-type, & td:first-of-type": {
                position: "sticky", left: 0, zIndex: 1, bgcolor: "background.paper",
                borderRight: 1, borderRightColor: "divider",
              },
              "& th:first-of-type": { zIndex: 3 },
              "& tbody .MuiIconButton-root": { width: 32, height: 32 },
            }}
          >
            <TableHead>
              <TableRow>
                <TableCell sx={{ minWidth: 300, width: 300 }}>
                  <TableSortLabel
                    active={sortKey === "username"}
                    direction={sortKey === "username" ? sortDir : "asc"}
                    onClick={() => toggleSort("username")}
                  >
                    {t("vpnUsers.user")}
                  </TableSortLabel>
                </TableCell>
                <TableCell sx={{ minWidth: 160, width: 160 }}>
                  <TableSortLabel
                    active={sortKey === "enabled"}
                    direction={sortKey === "enabled" ? sortDir : "asc"}
                    onClick={() => toggleSort("enabled")}
                  >
                    {t("vpnUsers.status")}
                  </TableSortLabel>
                </TableCell>
                {servers.map((s) => (
                  <TableCell key={s.id} align="center" sx={{ minWidth: 220, width: 220 }}>
                    <TableSortLabel
                      active={sortKey === `server:${s.id}`}
                      direction={sortKey === `server:${s.id}` ? sortDir : "asc"}
                      onClick={() => toggleSort(`server:${s.id}`)}
                      sx={{ maxWidth: 180, whiteSpace: "normal", overflowWrap: "anywhere" }}
                    >
                      {s.display_name}
                    </TableSortLabel>
                  </TableCell>
                ))}
              </TableRow>

              {/* Filter row — one control per column, mirroring the header. */}
              <TableRow>
                <TableCell sx={{ py: 0.5 }}>
                  <FilterCell
                    active={Boolean(fUser)}
                    onClear={() => setFUser("")}
                    title={t("vpnUsers.clearColumn")}
                  >
                    <TextField
                      size="small"
                      fullWidth
                      placeholder={t("vpnUsers.search")}
                      value={fUser}
                      onChange={(e) => setFUser(e.target.value)}
                      slotProps={{ input: { sx: { fontSize: 13 } } }}
                    />
                  </FilterCell>
                </TableCell>
                <TableCell sx={{ py: 0.5 }}>
                  <FilterCell
                    active={Boolean(fEnabled)}
                    onClear={() => setFEnabled("")}
                    title={t("vpnUsers.clearColumn")}
                  >
                    <Select
                      size="small"
                      fullWidth
                      displayEmpty
                      value={fEnabled}
                      onChange={(e) => setFEnabled(e.target.value as typeof fEnabled)}
                      sx={selectSx}
                    >
                      <MenuItem value="">{t("vpnUsers.filterAllStatus")}</MenuItem>
                      <MenuItem value="on">{t("vpnUsers.filterEnabled")}</MenuItem>
                      <MenuItem value="off">{t("vpnUsers.filterDisabled")}</MenuItem>
                    </Select>
                  </FilterCell>
                </TableCell>
                {servers.map((s) => {
                  const picked = fServer[s.id] ?? [];
                  return (
                    <TableCell key={s.id} align="center" sx={{ py: 0.5 }}>
                      <FilterCell
                        active={picked.length > 0}
                        onClear={() => setFServer((f) => ({ ...f, [s.id]: [] }))}
                        title={t("vpnUsers.clearColumn")}
                      >
                      <Select
                        multiple
                        size="small"
                        fullWidth
                        displayEmpty
                        value={picked}
                        onChange={(e) => {
                          // Defensive: MUI hands back whatever the clicked
                          // child carried as `value`.
                          const v = (e.target.value as (ServerFilter | undefined)[])
                            .filter(Boolean) as ServerFilter[];
                          setFServer((f) => ({ ...f, [s.id]: v }));
                        }}
                        renderValue={(sel) =>
                          sel.length === 0 ? (
                            <Box component="span" sx={{ color: "text.secondary" }}>
                              {t("vpnUsers.filterAll")}
                            </Box>
                          ) : (
                            <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5, justifyContent: "center" }}>
                              {sel.map((f) => <FilterIcon key={f} kind={f} />)}
                            </Box>
                          )
                        }
                        sx={selectSx}
                      >
                        {SERVER_FILTERS.map((f) => (
                          <MenuItem key={f} value={f} dense>
                            <Checkbox size="small" checked={picked.includes(f)} sx={{ py: 0 }} />
                            <ListItemIcon sx={{ minWidth: 30 }}><FilterIcon kind={f} /></ListItemIcon>
                            <ListItemText primary={t(FILTER_LABEL[f])} />
                          </MenuItem>
                        ))}
                      </Select>
                      </FilterCell>
                    </TableCell>
                  );
                })}
              </TableRow>
            </TableHead>

            <TableBody>
              {visible.map((u) => (
                <TableRow key={u.id} hover>
                  <TableCell>
                    <Box sx={{ display: "flex", alignItems: "center", gap: 1, minWidth: 0 }}>
                    <Box
                      component="button"
                      onClick={() => setDialogUser(u)}
                      disabled={savingChannels.has(u.id)}
                      sx={{
                        background: "none", border: 0, p: 0, cursor: "pointer",
                        color: "primary.main", textAlign: "left", font: "inherit",
                        minWidth: 0, flex: "1 1 auto", maxWidth: 208, overflowWrap: "anywhere", fontWeight: 600,
                      }}
                    >
                      {u.username}
                    </Box>
                    <Select
                      size="small"
                      value={u.update_channel}
                      disabled={savingChannels.has(u.id)}
                      inputProps={{ "aria-label": `${t("vpnUsers.updateChannel")}: ${u.username}` }}
                      onClick={(e) => e.stopPropagation()}
                      onMouseDown={(e) => e.stopPropagation()}
                      onKeyDown={(e) => e.stopPropagation()}
                      onChange={(e) => changeChannel(u, e.target.value as VpnUser["update_channel"])}
                      sx={{ ...selectSx, minWidth: 112, flexShrink: 0 }}
                    >
                      <MenuItem value="stable">{t("vpnUsers.updateChannelStable")}</MenuItem>
                      <MenuItem value="beta">{t("vpnUsers.updateChannelBeta")}</MenuItem>
                    </Select>
                    </Box>
                    {u.full_name && (
                      <Typography variant="caption" sx={{ display: "block", maxWidth: 208, overflowWrap: "anywhere", color: "text.secondary" }}>
                        {u.full_name}
                      </Typography>
                    )}
                  </TableCell>

                  <TableCell>
                    <Chip
                      size="small"
                      color={u.enabled ? "success" : "default"}
                      variant={u.enabled ? "filled" : "outlined"}
                      label={u.enabled ? t("vpnUsers.filterEnabled") : t("vpnUsers.filterDisabled")}
                    />
                  </TableCell>

                  {servers.map((s) => {
                    const cell = cellOf(u, s.id);
                    const key = `${u.id}:${s.id}`;
                    const pending = cell && cell.sync_status !== "synced";
                    const published = serverProfiles[String(s.id)] ?? [];
                    const routes = cell?.allowed_profiles ?? [];
                    // Names, not slot ids: the label is what the user sees in
                    // their client, so it is what an admin should be shown too.
                    const routeNames = published
                      .filter((pr) => routes.includes(pr.slot_id))
                      .map((pr) => pr.label);
                    const routeTitle = !cell
                      ? ""
                      : published.length === 0
                        ? t("vpnUsers.routeNonePublished")
                        : routeNames.length > 0
                          ? t("vpnUsers.routeOnHint", { routes: routeNames.join(", ") })
                          : published.length === 1
                            ? t("vpnUsers.routeGrantHint", { route: published[0].label })
                            : t("vpnUsers.routeChooseHint");
                    return (
                      <TableCell key={s.id} align="center" sx={{ whiteSpace: "nowrap" }}>
                        <Tooltip title={cell ? t("vpnUsers.revokeHint") : t("vpnUsers.grantHint")}>
                          <span>
                            <IconButton
                              size="small"
                              disabled={busy === key}
                              onClick={() => (cell ? setRevoking({ user: u, server: s }) : grant(u, s, {}))}
                            >
                              {cell
                                ? <CheckCircleIcon fontSize="small" color={pending ? "warning" : "success"} />
                                : <RadioButtonUncheckedIcon fontSize="small" sx={{ color: "action.disabled" }} />}
                            </IconButton>
                          </span>
                        </Tooltip>

                        <Tooltip title={!cell ? "" : cell.lan_access ? t("vpnUsers.lanOnHint") : t("vpnUsers.lanOffHint")}>
                          <span>
                            <IconButton
                              size="small"
                              disabled={!cell || busy === key}
                              onClick={() => cell && grant(u, s, { lan_access: !cell.lan_access })}
                            >
                              {cell?.lan_access
                                ? <LanIcon fontSize="small" color="primary" />
                                : <BlockIcon fontSize="small" sx={{ color: cell ? "error.main" : "action.disabledBackground" }} />}
                            </IconButton>
                          </span>
                        </Tooltip>

                        <Tooltip title={t("vpnUsers.allowSmartTest")}>
                          <span>
                            <IconButton
                              size="small"
                              aria-label={t("vpnUsers.allowSmartTest")}
                              aria-pressed={cell?.allow_smart_test ?? false}
                              disabled={!cell || busy === key}
                              onClick={() => cell && grant(u, s, { allow_smart_test: !cell.allow_smart_test })}
                            >
                              <ScienceIcon fontSize="small" color={cell?.allow_smart_test ? "primary" : "disabled"} />
                            </IconButton>
                          </span>
                        </Tooltip>

                        {/* The third axis. It was reachable only from the
                            detail dialog, so the matrix — the one view whose
                            job is "who has what, at a glance" — showed two of
                            the three things a user can be granted.

                            One published route is a plain toggle like the
                            other two. Several cannot be: a click has no way to
                            say which, so it opens the dialog that can. The
                            tooltip says which of the two will happen. */}
                        <Tooltip title={routeTitle}>
                          <span>
                            <IconButton
                              size="small"
                              disabled={!cell || published.length === 0 || busy === key}
                              onClick={() => {
                                if (!cell) return;
                                if (published.length !== 1) return setDialogUser(u);
                                const only = published[0].slot_id;
                                grant(u, s, {
                                  allowed_profiles: routes.includes(only)
                                    ? routes.filter((r) => r !== only)
                                    : [...routes, only],
                                });
                              }}
                            >
                              <AltRouteIcon
                                fontSize="small"
                                sx={{
                                  color: routes.length > 0
                                    ? "info.main"
                                    : cell && published.length > 0
                                      ? "action.disabled"
                                      : "action.disabledBackground",
                                }}
                              />
                            </IconButton>
                          </span>
                        </Tooltip>
                      </TableCell>
                    );
                  })}
                </TableRow>
              ))}
              {visible.length === 0 && (
                <TableRow>
                  <TableCell colSpan={servers.length + 2}>
                    <Typography color="text.secondary" sx={{ py: 2, textAlign: "center" }}>
                      {t("vpnUsers.noUsers")}
                    </Typography>
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </TableContainer>
      )}

      <Typography variant="caption" sx={{ display: "block", mt: 1, color: "text.secondary" }}>
        {t("vpnUsers.legend")}
      </Typography>

      {dialogUser !== null && (
        <VpnUserDialog
          isSuperadmin={isSuperadmin}
          user={dialogUser === "new" ? null : dialogUser}
          servers={servers}
          onClose={() => setDialogUser(null)}
          onSaved={() => { setDialogUser(null); fetchAll(); }}
        />
      )}

      {revoking && (
        <ConfirmRevokeDialog
          username={revoking.user.username}
          serverName={revoking.server.display_name}
          onCancel={() => setRevoking(null)}
          onConfirm={confirmRevoke}
        />
      )}

      <Snackbar
        open={Boolean(snack)}
        autoHideDuration={snack?.error || snack?.warn ? 8000 : 3000}
        onClose={() => setSnack(null)}
        anchorOrigin={{ vertical: "bottom", horizontal: "center" }}
      >
        <Alert
          severity={snack?.error ? "error" : snack?.warn ? "warning" : "success"}
          onClose={() => setSnack(null)}
        >
          {snack?.msg}
        </Alert>
      </Snackbar>
    </Box>
  );
}
