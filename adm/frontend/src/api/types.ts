export interface Server {
  id: number;
  name: string;
  display_name: string;
  ip: string;
  public_ip: string;
  server_type: "vpn_exit" | "dpi_bypass";
  location: string;
  provider: string;
  status: string;
  agent_port: number;
  online: boolean;
  agent_status: AgentStatus | null;
  error: string | null;
}

export interface AgentStatus {
  hostname: string;
  uptime: number;
  server_type: string;
  public_ip: string;
  disk: { free_gb: number; total_gb: number; used_gb: number; used_pct: number };
  memory: { available_mb: number; total_mb: number; used_pct: number };
  cpu?: { used_pct: number };
  services: Record<string, boolean>;
  docker_containers?: ContainerInfo[];
  version?: string;
}

export interface ContainerInfo {
  name: string;
  status: string;
  running: boolean;
}

export interface ServerDetail extends Server {
  ss_password: string | null;
  agent_api_key: string | null;
  ssconf_token: string | null;
  ss_port: number;
  ss_cipher: string;
  node_id: string | null;
  install_adguard: number;
  callhome_ip: string | null;
  traffic: TrafficUsage | null;
  created_at: number;
  updated_at: number;
  operations: Operation[];
}

export interface TrafficUsage {
  rx_gb: number;
  tx_gb: number;
  samples: number;
  /** Reboots seen in the window. The figure undercounts by whatever moved
   *  across each one, so the UI says so rather than implying precision. */
  counter_resets: number;
  period_start: number;
  limit_gb: number | null;
}

export interface MgmtTunnelData {
  address: string;
  interface: string;
  config: string;
  install: string;
}

export interface Operation {
  id: number;
  server_id: number | null;
  op_type: string;
  status: string;
  playbook: string | null;
  output?: string;
  error: string | null;
  started_at: number;
  completed_at: number | null;
}

export type AdminRole = "superadmin" | "admin";

export interface AuthMe {
  auth_configured: boolean;
  username?: string;
  role?: AdminRole;
  /** VPN server ids a scoped admin may manage. Empty for a superadmin. */
  scope?: number[];
}

/** Whether an operator can sign into one site's own Proxima panel. */
export interface PanelAccess {
  vpn_server_id: number;
  sync_status: "pending" | "synced" | "pending_delete";
  sync_error: string | null;
  synced_at: number | null;
}

export interface Admin {
  id: number;
  username: string;
  role: AdminRole;
  enabled: boolean;
  created_at: number;
  /** Whose users they may edit here — not the same as `access`. */
  scope: number[];
  /** Which site panels they can log into. */
  access: PanelAccess[];
  /** Only present in the response that created it or reset the password. */
  password?: string;
}

export interface VlessKeyData {
  uri: string;
  server: string;
  port: number;
  vless_uuid: string;
  public_key: string;
  short_id: string;
  server_name: string;
  flow: string;
  fingerprint: string;
}

// ── VPN Servers (Proxima instances) ─────────────────────────────────────

export interface DeployedVersion {
  commit: string;
  short: string;
  committed_at: number | null;
  deployed_at: number | null;
  source: string | null;
}

export interface SourceRevision {
  commit: string;
  short: string;
  committed_at: number;
}

export interface VpnServer {
  id: number;
  name: string;
  display_name: string;
  url: string;
  public_url: string;
  /** The DB-stored public URL — what single-login discovery returns to
   *  clients. public_url above may be masked by the instance's live value. */
  discovery_url: string;
  has_token: boolean;
  /** "none" | "expired" | "expiring" | "ok" — read from the stored JWT. */
  token_state: "none" | "expired" | "expiring" | "ok";
  token_expires_at: number | null;
  online: boolean;
  proxima_status: ProximaStatus | null;
  connectivity: ServiceStatus[] | null;
  error: string | null;
}

/** How Ansible reaches the site, as the detail view reports it. Empty means the
 *  site has no ssh_host and is therefore absent from proxima_sites — it has no
 *  update path. */
export interface VpnServerManagement {
  ssh_host: string;
  ssh_port: number;
  ssh_user: string;
}

export interface ServiceStatus {
  id: string;
  accessible: boolean;
  checked_at: string | null;
  error: string | null;
  latency_ms: number | null;
}

export interface ProximaSystemMetrics {
  cpu?: { used_pct: number };
  memory?: { total_mb: number; available_mb: number; used_pct: number };
  disk?: { total_gb: number; used_gb: number; used_pct: number };
}

export interface ProximaStatus {
  server_ip: string;
  mode: string;
  deployment: string;
  dns_mode: { active: boolean; containers: Record<string, string> };
  slots: Record<string, ProximaSlotSummary>;
  bypass_active: boolean;
  bypass_slots: string[];
  system?: ProximaSystemMetrics;
  /** Null when the server was not deployed by ADM. */
  version?: DeployedVersion | null;
}

export interface ProximaSlotSummary {
  label: string;
  type: string;
  active: string | null;
  pool: string[];
  enabled?: boolean;
  health: {
    last_ip_ok: boolean | null;
    last_ip: string | null;
    failover_count: number;
    bypass_active: boolean;
  };
}

export interface ProximaSlot {
  id: string;
  label: string;
  type: string;
  enabled: boolean;
  port: number;
  socks_port: number;
  direct: boolean;
  active: string | null;
  pool: string[];
  dpi_args?: string | null;
  via_slot?: string | null;
  health: {
    last_ip_check: string | null;
    last_ip_ok: boolean | null;
    last_ip: string | null;
    last_domain_check: string | null;
    last_domain_ok: boolean | null;
    domain_ok_count: number | null;
    domain_total_count: number | null;
    failover_count: number;
    key_stats: Record<string, unknown>;
  };
}

export interface ProximaTunnel {
  name: string;
  type: "awg" | "outline" | "xray";
  endpoint: string;
  method?: string | null;
  ssconf_url?: string;
  location?: string;
  tag?: string;
  prefix?: string;
  server?: string;
  port?: number;
  vless_uuid?: string;
  public_key?: string;
  short_id?: string;
  server_name?: string;
  flow?: string;
  fingerprint?: string;
}

// ── Monitoring ────────────────────────────────────────────────────────

// Over ranges longer than a day the backend averages samples into time
// buckets: `*_pct` is the bucket average, `*_max` its peak. Both are absent
// on raw (24h) responses.
export interface MetricPoint {
  server_id: number;
  timestamp: number;
  online: number;
  disk_pct: number | null;
  memory_pct: number | null;
  cpu_pct: number | null;
  disk_max?: number | null;
  memory_max?: number | null;
  cpu_max?: number | null;
  uptime: number | null;
}

export interface VpnMetricPoint {
  vpn_server_id: number;
  timestamp: number;
  online: number;
  disk_pct: number | null;
  memory_pct: number | null;
  cpu_pct: number | null;
  disk_max?: number | null;
  memory_max?: number | null;
  cpu_max?: number | null;
}

export interface AlertConfig {
  enabled: number;
  telegram_bot_token: string;
  telegram_chat_id: string;
  disk_threshold: number;
  memory_threshold: number;
  cpu_threshold: number;
  offline_minutes: number;
}

export interface AlertEntry {
  id: number;
  server_id: number | null;
  alert_type: string;
  message: string;
  sent_at: number;
  server_name: string | null;
}

export interface PreflightConflict {
  type: "port" | "service" | "container" | "virtualisation" | "tun" | "modules";
  port?: number;
  name?: string;
  detail: string;
  /** "blocker" means the box cannot be an exit node at all — container
   *  virtualisation, or no /dev/net/tun. Not a warning to weigh up. */
  severity: "blocker" | "warning" | "info";
}

export interface PreflightData {
  os: string;
  arch: string;
  python: string;
  virt: string;
  tun_device: string;
  kernel_modules: string;
  disk_free_gb: number;
  memory_mb: number;
  occupied_ports: { port: number; process: string }[];
  active_services: { name: string; state: string }[];
  docker_containers: { name: string; image: string; status: string }[];
  conflicts: PreflightConflict[];
  ssh_ok: boolean;
}

// ── Central VPN users ────────────────────────────────────────────────────

export interface VpnUserAccess {
  vpn_server_id: number;
  server_name: string;
  server_display_name: string;
  remote_user_id: number | null;
  enabled: boolean;
  lan_access: boolean;
  allow_smart_test: boolean;
  max_peers: number | null;
  bandwidth_quota: number | null;
  speed_download: string | null;
  speed_upload: string | null;
  assigned_groups: string[];
  /** Published Direct-profile slot ids this user may pick on that site. */
  allowed_profiles: string[];
  sync_status: "synced" | "pending" | "pending_delete" | "error";
  sync_error: string | null;
  synced_at: number | null;
}

/** A Direct profile a site publishes, as last seen by ADM's poller. */
export interface ServerProfile {
  slot_id: string;
  label: string;
  description: string;
  enabled: boolean;
  /** null when the site has not run an IP check for that slot yet. */
  last_ip_ok: boolean | null;
}

export interface ServerProfiles {
  server_name: string;
  server_display_name: string;
  cached_at: number | null;
  profiles: ServerProfile[];
}

export interface VpnUser {
  id: number;
  username: string;
  full_name: string;
  enabled: boolean;
  note: string;
  created_at: number;
  updated_at: number;
  servers: VpnUserAccess[];
  /** Only present in the response that created or reset it. */
  password?: string;
  sync?: SyncResult;
}

export interface SyncResult {
  created?: string[];
  adopted?: string[];
  updated?: string[];
  recreated?: string[];
  removed?: string[];
  failed?: { target: string; error: string; action?: string }[];
}

export interface SyncSummary {
  synced: number;
  pending: number;
  pending_delete: number;
  error: number;
  errors: { username: string; server_name: string; sync_error: string }[];
}

/** One range already spoken for, shown so the next one is picked knowingly. */
export interface SubnetRange {
  network: string;
  owner: string;
  kind: "management" | "ProximaVPN" | "LAN";
}
