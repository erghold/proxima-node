import { useCallback, useEffect, useState } from "react";
import { Alert, Box, Button, Checkbox, Chip, Dialog, DialogActions, DialogContent, DialogTitle, FormControlLabel, MenuItem, Paper, Stack, TextField, Typography } from "@mui/material";
import { useTranslation } from "react-i18next";
import api from "../api/client";
import type { VpnUser } from "../api/types";

type Kind = "smart" | "lan_only" | "full_tunnel";
type Member = { site_id: number; route_id: string };
type Pool = { schema_version: number; id: string; label: string; kind: Kind; enabled: boolean; policy_revision: number; members: Member[]; user_ids: number[] };
type Inventory = Record<string, { server_display_name: string; server_name: string; routes: { route_id: string; label: string; kind: Kind; enabled: boolean; available: boolean; stale: boolean }[] }>;
const kinds: Kind[] = ["smart", "lan_only", "full_tunnel"];

export default function PoolsTab() {
  const { t } = useTranslation();
  const [pools, setPools] = useState<Pool[]>([]);
  const [inventory, setInventory] = useState<Inventory>({});
  const [users, setUsers] = useState<VpnUser[]>([]);
  const [draft, setDraft] = useState<Pool | null>(null);
  const [grants, setGrants] = useState<string | null>(null);
  const [site, setSite] = useState("");
  const [route, setRoute] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const failure = (e: unknown) => setError((e as { response?: { data?: { error?: string } } }).response?.data?.error || t("common.error"));
  const load = useCallback(async () => {
    const [p, i, u] = await Promise.all([api.get("/pool-catalog"), api.get("/vpn-servers/profiles"), api.get("/vpn-users")]);
    setPools(p.data.data.filter((item: Pool) => item.schema_version === 2));
    setInventory(i.data.data);
    setUsers(u.data.data);
  }, []);
  useEffect(() => { load().catch(failure); }, [load]); // eslint-disable-line react-hooks/exhaustive-deps
  const save = async () => {
    if (!draft) return;
    setBusy(true); setError("");
    const body = { schema_version: 2, label: draft.label, kind: draft.kind, enabled: draft.enabled,
      members: draft.members.map(({ site_id, route_id }) => ({ site_id, route_id })),
      ...(draft.id ? { policy_revision: draft.policy_revision } : {}) };
    try {
      if (draft.id) await api.put(`/pool-catalog/${draft.id}`, body);
      else await api.post("/pool-catalog", body);
      setDraft(null); await load();
    } catch (e) { failure(e); } finally { setBusy(false); }
  };
  const move = (index: number, direction: number) => {
    if (!draft) return;
    const members = [...draft.members];
    [members[index], members[index + direction]] = [members[index + direction], members[index]];
    setDraft({ ...draft, members });
  };
  const memberLabel = (m: Member) => {
    const s = inventory[String(m.site_id)];
    const r = s?.routes.find(item => item.route_id === m.route_id);
    return `${s?.server_display_name || s?.server_name || m.site_id} / ${r?.label || m.route_id}`;
  };
  const selected = pools.find(p => p.id === grants);
  return <Stack spacing={2}>
    <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
      <Button variant="contained" onClick={() => { setError(""); setSite(""); setRoute(""); setDraft({ schema_version: 2, id: "", label: "", kind: "full_tunnel", enabled: false, policy_revision: 0, members: [], user_ids: [] }); }}>{t("pools.create")}</Button>
      <Button onClick={() => load().catch(failure)}>{t("dashboard.refresh")}</Button>
    </Box>
    <Alert severity="info">{t("pools.description")}</Alert>
    {error && <Alert severity="error">{error}</Alert>}
    {pools.map(p => <Paper key={p.id} sx={{ p: 2 }}>
      <Stack spacing={1}>
        <Typography variant="h6">{p.label}</Typography>
        <Box><Chip label={t(`pools.${p.kind}`)} /> <Chip label={t(p.enabled ? "pools.enabled" : "pools.disabled")} /></Box>
        {p.members.map((m, index) => {
          const r = inventory[String(m.site_id)]?.routes.find(item => item.route_id === m.route_id);
          return <Typography key={`${m.site_id}/${m.route_id}`} color={r?.available ? "text.primary" : "warning.main"}>{index + 1}. {memberLabel(m)} {!r?.available && `— ${t(r?.stale ? "pools.stale" : "pools.unavailable")}`}</Typography>;
        })}
        <Box><Button onClick={() => { setError(""); setSite(""); setRoute(""); setDraft({ ...p, members: [...p.members] }); }}>{t("pools.edit")}</Button><Button onClick={() => setGrants(p.id)}>{t("pools.grants")}</Button></Box>
      </Stack>
    </Paper>)}
    <Dialog open={!!draft} onClose={() => !busy && setDraft(null)} fullWidth maxWidth="md">
      <DialogTitle>{t(draft?.id ? "pools.edit" : "pools.create")}</DialogTitle>
      <DialogContent><Stack spacing={2} sx={{ pt: 1 }}>
        {error && <Alert severity="error">{error}</Alert>}
        <TextField label={t("pools.label")} value={draft?.label || ""} onChange={e => draft && setDraft({ ...draft, label: e.target.value })} slotProps={{ htmlInput: { maxLength: 100 } }} disabled={busy} />
        <TextField select label={t("pools.kind")} value={draft?.kind || "full_tunnel"} disabled={busy} onChange={e => { if (draft) setDraft({ ...draft, kind: e.target.value as Kind, members: [] }); setRoute(""); }}>
          {kinds.map(k => <MenuItem key={k} value={k}>{t(`pools.${k}`)}</MenuItem>)}
        </TextField>
        <FormControlLabel control={<Checkbox checked={draft?.enabled || false} disabled={busy} onChange={e => draft && setDraft({ ...draft, enabled: e.target.checked })} />} label={t("pools.enabled")} />
        <TextField select label={t("pools.site")} value={site} disabled={busy} onChange={e => { setSite(e.target.value); setRoute(""); }}>
          {Object.entries(inventory).map(([id, s]) => <MenuItem key={id} value={id}>{s.server_display_name || s.server_name}</MenuItem>)}
        </TextField>
        <TextField select label={t("pools.route")} value={route} disabled={busy || !site} onChange={e => setRoute(e.target.value)}>
          {(inventory[site]?.routes || []).filter(r => r.kind === draft?.kind).map(r => <MenuItem key={r.route_id} value={r.route_id}>{r.label} {!r.available && `— ${t(r.stale ? "pools.stale" : "pools.unavailable")}`}</MenuItem>)}
        </TextField>
        <Button disabled={busy || !site || !route || draft?.members.some(m => m.site_id === Number(site) && m.route_id === route)} onClick={() => draft && setDraft({ ...draft, members: [...draft.members, { site_id: Number(site), route_id: route }] })}>{t("pools.addMember")}</Button>
        {draft?.members.map((m, i) => <Box key={`${m.site_id}/${m.route_id}`} sx={{ display: "flex", alignItems: "center", flexWrap: "wrap" }}>
          <Typography sx={{ flex: 1 }}>{i + 1}. {memberLabel(m)}</Typography>
          <Button disabled={busy || i === 0} onClick={() => move(i, -1)}>{t("pools.up")}</Button>
          <Button disabled={busy || i === draft.members.length - 1} onClick={() => move(i, 1)}>{t("pools.down")}</Button>
          <Button disabled={busy} onClick={() => setDraft({ ...draft, members: draft.members.filter((_, j) => i !== j) })}>{t("pools.remove")}</Button>
        </Box>)}
      </Stack></DialogContent>
      <DialogActions><Button disabled={busy} onClick={() => setDraft(null)}>{t("common.cancel")}</Button><Button disabled={busy || !draft?.label.trim() || !draft.members.length} onClick={save}>{t("common.save")}</Button></DialogActions>
    </Dialog>
    <Dialog open={!!selected} onClose={() => !busy && setGrants(null)} fullWidth>
      <DialogTitle>{t("pools.grants")} — {selected?.label}</DialogTitle>
      <DialogContent><Alert severity="info">{t("pools.prerequisite")}</Alert>
        {error && <Alert severity="error">{error}</Alert>}
        {users.map(u => <Box key={u.id}><FormControlLabel label={`${u.username}${!u.allow_pools ? ` — ${t("pools.policyOff")}` : ""}`} control={<Checkbox checked={selected?.user_ids.includes(u.id) || false} disabled={busy} onChange={async e => {
          if (!selected) return;
          setBusy(true); setError("");
          try { await api.put(`/pool-catalog/${selected.id}/users/${u.id}`, { enabled: e.target.checked }); await load(); }
          catch (err) { failure(err); } finally { setBusy(false); }
        }} />} /></Box>)}
      </DialogContent><DialogActions><Button disabled={busy} onClick={() => setGrants(null)}>{t("common.close")}</Button></DialogActions>
    </Dialog>
  </Stack>;
}
