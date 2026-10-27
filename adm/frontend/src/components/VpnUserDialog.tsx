import { useEffect, useMemo, useState } from "react";
import {
  Alert, Box, Button, Checkbox, Chip, Dialog, DialogActions, DialogContent,
  DialogTitle, Divider, FormControlLabel, Grid2 as Grid, IconButton, Paper,
  MenuItem, Stack, TextField, Typography,
} from "@mui/material";
import ContentCopyIcon from "@mui/icons-material/ContentCopy";
import VisibilityIcon from "@mui/icons-material/Visibility";
import VisibilityOffIcon from "@mui/icons-material/VisibilityOff";
import { useTranslation } from "react-i18next";
import api from "../api/client";
import type {
  ServerProfile, ServerProfiles, VpnServer, VpnUser, VpnUserAccess,
} from "../api/types";

interface Props {
  isSuperadmin: boolean;
  user: VpnUser | null;          // null = create
  servers: VpnServer[];
  onClose: () => void;
  onSaved: () => void;
}

/** Per-server limits the admin can edit from the detail view. */
interface Draft {
  granted: boolean;
  lan_access: boolean;
  allow_smart_test: boolean;
  max_peers: string;
  /** Slot ids of the Direct profiles this user may pick on that site. */
  allowed_profiles: string[];
}

const MIN_PASSWORD = 8;
/** Mirrors USERNAME_RE in backend/api/vpn_users.py — keep the two in step. */
const USERNAME_RE = /^[a-z0-9]+(?:[._-][a-z0-9]+)*$/;

type SyncResult = {
  failed?: { target: string; error: string }[];
  deferred?: { target: string; server: string; error: string }[];
  unreachable_servers?: string[];
} | undefined;

/** The backend's own reason, not a generic "failed" — a 400 always carries one. */
const apiError = (err: unknown): string | undefined =>
  (err as { response?: { data?: { error?: string } } })?.response?.data?.error;

const syncFailures = (sync: SyncResult): string =>
  (sync?.failed ?? []).map((f) => `${f.target}: ${f.error}`).join(", ");

export default function VpnUserDialog({ user, servers, isSuperadmin, onClose, onSaved }: Props) {
  const { t } = useTranslation();
  const isNew = user === null;

  const [username, setUsername] = useState(user?.username ?? "");
  const [fullName, setFullName] = useState(user?.full_name ?? "");
  const [note, setNote] = useState(user?.note ?? "");
  const [enabled, setEnabled] = useState(user?.enabled ?? true);
  const [allowPools, setAllowPools] = useState(user?.allow_pools ?? false);
  const [updateChannel, setUpdateChannel] = useState<"stable" | "beta">(user?.update_channel === "beta" ? "beta" : "stable");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [drafts, setDrafts] = useState<Record<number, Draft>>(() => {
    const out: Record<number, Draft> = {};
    for (const s of servers) {
      const a: VpnUserAccess | undefined = user?.servers.find((x) => x.vpn_server_id === s.id);
      out[s.id] = {
        granted: Boolean(a),
        lan_access: a?.lan_access ?? true,
        allow_smart_test: a?.allow_smart_test ?? false,
        max_peers: a?.max_peers != null ? String(a.max_peers) : "",
        allowed_profiles: a?.allowed_profiles ?? [],
      };
    }
    return out;
  });

  /** Published Direct profiles per server id, from ADM's poller cache.
   *  Cached server-side, so an unreachable site still renders its options. */
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
      .catch(() => { /* the dialog still works without them */ });
    return () => { cancelled = true; };
  }, []);

  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  /** Set once the password was accepted, so the onboarding block can be built. */
  const [issued, setIssued] = useState<{ password: string } | null>(null);
  /** The account was saved but a site did not take it — shown with the package. */
  const [pushError, setPushError] = useState("");
  const [copied, setCopied] = useState(false);

  // Counted after trimming, as the backend does — "1234567 " is 7 characters there.
  const passwordLen = password.trim().length;
  const tooShort = passwordLen > 0 && passwordLen < MIN_PASSWORD;
  const normalizedUsername = username.trim().toLowerCase();
  const usernameInvalid =
    isNew && normalizedUsername.length > 0 && !USERNAME_RE.test(normalizedUsername);

  const setDraft = (id: number, patch: Partial<Draft>) =>
    setDrafts((d) => ({ ...d, [id]: { ...d[id], ...patch } }));

  const grantedServers = useMemo(
    () => servers.filter((s) => drafts[s.id]?.granted),
    [servers, drafts],
  );

  /** The single block an admin hands over. One section per authorized site. */
  const onboarding = useMemo(() => {
    if (!issued) return "";
    const lines = grantedServers.map((s) => {
      const addr = s.public_url || s.url;
      return [
        s.display_name,
        `  ${t("vpnUsers.pkgAddress")}: ${addr}`,
        `  ${t("vpnUsers.pkgUsername")}: ${username}`,
        `  ${t("vpnUsers.pkgPassword")}: ${issued.password}`,
      ].join("\n");
    });
    return `${t("vpnUsers.pkgHeader")}\n\n${lines.join("\n\n")}`;
  }, [issued, grantedServers, username, t]);

  const copyPackage = async () => {
    await navigator.clipboard.writeText(onboarding);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const accessBody = (id: number) => {
    const d = drafts[id];
    return {
      lan_access: d.lan_access,
      allow_smart_test: d.allow_smart_test,
      max_peers: d.max_peers.trim() === "" ? null : Number(d.max_peers),
      allowed_profiles: d.allowed_profiles,
    };
  };

  const save = async () => {
    setError("");
    setSaving(true);
    try {
      if (isNew) {
        const { data } = await api.post("/vpn-users", {
          username: normalizedUsername,
          full_name: fullName.trim(),
          note: note.trim(),
          password: password.trim(),
          enabled,
          update_channel: updateChannel,
          ...(isSuperadmin ? { allow_pools: allowPools } : {}),
          servers: grantedServers.map((s) => ({ vpn_server_id: s.id, ...accessBody(s.id) })),
        });
        if (!data.ok) { setError(data.error); setSaving(false); return; }
        // Stay open and show the block to hand over.
        const failed = syncFailures(data.data.sync);
        const waiting = data.data.sync?.deferred ?? [];
        if (failed) setPushError(t("vpnUsers.syncFailed", { detail: failed }));
        else if (waiting.length) {
          setPushError(t("vpnUsers.syncWaiting", {
            n: waiting.length,
            servers: (data.data.sync?.unreachable_servers ?? []).join(", "),
          }));
        }
        setIssued({ password: data.data.password });
        setSaving(false);
        return;
      }

      const { data } = await api.put(`/vpn-users/${user!.id}`, {
        full_name: fullName.trim(),
        note: note.trim(),
        enabled,
        update_channel: updateChannel,
        ...(isSuperadmin ? { allow_pools: allowPools } : {}),
      });
      if (!data.ok) { setError(data.error); setSaving(false); return; }

      if (password.trim()) {
        const res = await api.post(`/vpn-users/${user!.id}/password`, {
          password: password.trim(),
        });
        if (!res.data.ok) { setError(res.data.error); setSaving(false); return; }
      }

      // Grants: add or update the ones ticked. Revoking is deliberately not
      // done here — it destroys peers, so it goes through the matrix
      // confirmation instead.
      const failures: string[] = [];
      for (const s of servers) {
        if (!drafts[s.id].granted) continue;
        const res = await api.put(`/vpn-users/${user!.id}/access/${s.id}`, accessBody(s.id));
        const failed = syncFailures(res.data.data?.sync);
        if (failed) failures.push(failed);
      }
      const pushFailed = failures.length
        ? t("vpnUsers.syncFailed", { detail: failures.join(", ") })
        : "";

      if (password.trim()) {
        setPushError(pushFailed);
        setIssued({ password: password.trim() });
        setSaving(false);
        return;
      }
      if (pushFailed) { setError(pushFailed); setSaving(false); return; }
      onSaved();
    } catch (err: unknown) {
      setError(apiError(err) || t("vpnUsers.requestFailed"));
    }
    setSaving(false);
  };

  const canSave =
    normalizedUsername.length > 0 &&
    !usernameInvalid &&
    !tooShort &&
    (!isNew || passwordLen >= MIN_PASSWORD);

  return (
    <Dialog open onClose={issued ? onSaved : onClose} maxWidth="md" fullWidth sx={{ "& .MuiDialogTitle-root": { overflowWrap: "anywhere" }, "& .MuiAlert-message": { minWidth: 0, overflowWrap: "anywhere" } }}>
      <DialogTitle>{isNew ? t("vpnUsers.addUser") : username}</DialogTitle>
      <DialogContent dividers>
        {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}

        {issued ? (
          <Box>
            {pushError && <Alert severity="warning" sx={{ mb: 2 }}>{pushError}</Alert>}
            <Alert severity="info" sx={{ mb: 2 }}>{t("vpnUsers.packageHint")}</Alert>
            <TextField
              multiline
              fullWidth
              value={onboarding}
              slotProps={{
                input: { readOnly: true, sx: { fontFamily: "monospace", fontSize: 13 } },
              }}
            />
            <Button
              sx={{ mt: 2 }}
              startIcon={<ContentCopyIcon />}
              onClick={copyPackage}
              variant="contained"
            >
              {copied ? t("detail.copied") : t("vpnUsers.copyPackage")}
            </Button>
          </Box>
        ) : (
          <Stack spacing={3} sx={{ mt: 1 }}>
            <Grid container spacing={2}>
              {isSuperadmin && <Grid size={12}>
                <FormControlLabel
                  control={<Checkbox checked={allowPools} onChange={(e) => {
                    setAllowPools(e.target.checked);
                    setUpdateChannel(e.target.checked ? "beta" : "stable");
                  }} />}
                  label={t("vpnUsers.enablePoolBeta")}
                />
              </Grid>}
              <Grid size={{ xs: 12, sm: 6 }}>
                <TextField
                  select fullWidth
                  label={t("vpnUsers.updateChannel")}
                  helperText={t("vpnUsers.updateChannelHelp")}
                  value={updateChannel}
                  onChange={(e) => setUpdateChannel(e.target.value as "stable" | "beta")}
                >
                  <MenuItem value="stable">{t("vpnUsers.updateChannelStable")}</MenuItem>
                  <MenuItem value="beta">{t("vpnUsers.updateChannelBeta")}</MenuItem>
                </TextField>
              </Grid>
              <Grid size={{ xs: 12, sm: 6 }}>
                <TextField
                  label={t("vpnUsers.username")}
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  disabled={!isNew}
                  error={usernameInvalid}
                  helperText={
                    usernameInvalid
                      ? t("vpnUsers.usernameInvalid")
                      : isNew ? t("vpnUsers.usernameHelp") : t("vpnUsers.usernameLocked")
                  }
                  fullWidth
                />
              </Grid>
              <Grid size={{ xs: 12, sm: 6 }}>
                <TextField
                  label={t("vpnUsers.fullName")}
                  value={fullName}
                  onChange={(e) => setFullName(e.target.value)}
                  fullWidth
                />
              </Grid>
              <Grid size={{ xs: 12, sm: 6 }}>
                <TextField
                  label={isNew ? t("vpnUsers.password") : t("vpnUsers.newPassword")}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  type={showPassword ? "text" : "password"}
                  error={tooShort}
                  helperText={
                    tooShort
                      ? t("vpnUsers.passwordTooShort", { min: MIN_PASSWORD })
                      : isNew
                        ? t("vpnUsers.passwordHelp", { min: MIN_PASSWORD })
                        : t("vpnUsers.newPasswordHelp")
                  }
                  fullWidth
                  slotProps={{
                    input: {
                      endAdornment: (
                        <IconButton size="small" onClick={() => setShowPassword((v) => !v)}>
                          {showPassword ? <VisibilityOffIcon fontSize="small" /> : <VisibilityIcon fontSize="small" />}
                        </IconButton>
                      ),
                    },
                  }}
                />
              </Grid>
              <Grid size={{ xs: 12, sm: 6 }}>
                <TextField
                  label={t("vpnUsers.note")}
                  value={note}
                  onChange={(e) => setNote(e.target.value)}
                  fullWidth
                />
              </Grid>
              <Grid size={12}>
                <FormControlLabel
                  control={<Checkbox checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />}
                  label={t("vpnUsers.accountEnabled")}
                />
              </Grid>
            </Grid>

            <Divider />

            <Box>
                <Typography variant="subtitle2" sx={{ mb: 1.5, fontWeight: 700 }}>
                {t("vpnUsers.serverAccess")}
              </Typography>
              <Grid container spacing={2}>
                {servers.map((s) => {
                  const d = drafts[s.id];
                  const existing = user?.servers.find((x) => x.vpn_server_id === s.id);
                  return (
                    <Grid key={s.id} size={{ xs: 12, md: 6 }}>
                      <Paper
                        variant="outlined"
                        sx={{ p: 1.5, minWidth: 0, overflowWrap: "anywhere", opacity: d.granted ? 1 : 0.6, height: "100%", "& .MuiFormControlLabel-label": { minWidth: 0 } }}
                      >
                        <Box sx={{ display: "flex", alignItems: "center", gap: 1, flexWrap: "wrap" }}>
                          <FormControlLabel
                            sx={{ flex: { xs: "1 1 100%", sm: 1 }, minWidth: 0, mx: 0 }}
                            control={
                              <Checkbox
                                checked={d.granted}
                                disabled={Boolean(existing)}
                                onChange={(e) => setDraft(s.id, { granted: e.target.checked })}
                              />
                            }
                            label={s.display_name}
                          />
                          {existing && existing.sync_status !== "synced" && (
                            <Chip size="small" color="warning" label={existing.sync_status} />
                          )}
                        </Box>

                        {d.granted ? (
                          <Stack spacing={1} sx={{ pl: { xs: 0, sm: 4 }, pt: 0.5, minWidth: 0 }}>
                            <TextField
                              size="small"
                              label={t("vpnUsers.maxPeers")}
                              value={d.max_peers}
                              onChange={(e) => setDraft(s.id, { max_peers: e.target.value.replace(/\D/g, "") })}
                              placeholder={t("vpnUsers.unlimited")}
                              sx={{ width: 160, maxWidth: "100%" }}
                            />
                            <FormControlLabel
                              control={
                                <Checkbox
                                  checked={d.lan_access}
                                  onChange={(e) => setDraft(s.id, { lan_access: e.target.checked })}
                                />
                              }
                              label={t("vpnUsers.lanAccess")}
                            />
                            <FormControlLabel
                              control={
                                <Checkbox
                                  checked={d.allow_smart_test}
                                  onChange={(e) => setDraft(s.id, { allow_smart_test: e.target.checked })}
                                />
                              }
                              label={t("vpnUsers.allowSmartTest")}
                            />
                            {(serverProfiles[String(s.id)]?.length ?? 0) > 0 && (
                              <Box>
                                <Typography variant="caption" color="text.secondary">
                                  {t("vpnUsers.directRoutes")}
                                </Typography>
                                <Stack>
                                  {serverProfiles[String(s.id)].map((p) => (
                                    <FormControlLabel
                                      key={p.slot_id}
                                      sx={{ mx: 0, minWidth: 0 }}
                                      control={
                                        <Checkbox
                                          size="small"
                                          checked={d.allowed_profiles.includes(p.slot_id)}
                                          onChange={(e) =>
                                            setDraft(s.id, {
                                              allowed_profiles: e.target.checked
                                                ? [...d.allowed_profiles, p.slot_id]
                                                : d.allowed_profiles.filter((x) => x !== p.slot_id),
                                            })
                                          }
                                        />
                                      }
                                      label={
                                        <Stack direction="row" spacing={1} alignItems="center" sx={{ flexWrap: "wrap", minWidth: 0 }}>
                                          <Typography variant="body2" sx={{ minWidth: 0, overflowWrap: "anywhere" }}>{p.label}</Typography>
                                          {p.last_ip_ok === false && (
                                            <Chip
                                              size="small"
                                              color="warning"
                                              label={t("vpnUsers.profileUnhealthy")}
                                            />
                                          )}
                                        </Stack>
                                      }
                                    />
                                  ))}
                                </Stack>
                              </Box>
                            )}
                            {existing && (
                              <Typography variant="caption" color="text.secondary">
                                {t("vpnUsers.revokeFromMatrix")}
                              </Typography>
                            )}
                          </Stack>
                        ) : (
                          <Typography variant="caption" color="text.secondary" sx={{ pl: 4 }}>
                            {t("vpnUsers.notAuthorized")}
                          </Typography>
                        )}
                      </Paper>
                    </Grid>
                  );
                })}
              </Grid>
            </Box>
          </Stack>
        )}
      </DialogContent>
      <DialogActions sx={{ p: 2, gap: 1, flexWrap: "wrap", "& .MuiButton-root": { minHeight: 40 } }}>
        {issued ? (
          <Button variant="contained" onClick={onSaved}>{t("common.close")}</Button>
        ) : (
          <>
            <Button onClick={onClose}>{t("common.cancel")}</Button>
            <Button variant="contained" onClick={save} disabled={saving || !canSave}>
              {t("common.save")}
            </Button>
          </>
        )}
      </DialogActions>
    </Dialog>
  );
}
