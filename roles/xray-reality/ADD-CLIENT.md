# Dedicated ERG clients

This is a bounded exit-node change, not an ERG traffic migration. Release through
the authorized ADM source workflow first. Do not run the general install playbook
for client additions: its legacy post-task prints credentials (parent-owned fix).

From the ADM checkout, with its generated inventory and authorized SSH access:

```sh
ansible-playbook playbooks/add-xray-client.yml \
  -e xray_target=EXIT_INVENTORY_NAME \
  -e xray_client_label=erg-slot-6 \
  -e xray_client_server=EXIT_PUBLIC_HOSTNAME
```

One existing `vpn_exit` host only; repeat for each actual ERG slot. A stable label
reuses only that label's identity; a new label generates a new UUID. Do not rename
labels between retries. The endpoint is supplied explicitly, not the management
address. The playbook uses `/opt/xray-reality` and does not fetch credentials.

Each invocation also routes all provisioned `erg-slot-N` emails on that listener
through a dedicated `erg-ipv4` freedom outbound with `domainStrategy: UseIPv4`.
A first-match `user` rule lists each ERG email once; original outbounds (including
the default), original rules in their original relative order, Reality destination,
and non-ERG clients are unchanged. Existing ERG identities/profiles are not rotated:
rerun the same invocation to upgrade already provisioned clients. The first upgrade
changes configuration and restarts Xray; subsequent identical runs do not.

Conflicting `erg-ipv4` tags/rules, other explicit rules for ERG emails, matching
legacy balancer selectors, and cross-inbound email collisions are rejected rather
than overwritten. The label namespace is reserved for provisioned ERG identities.
`UseIPv4` selects IPv4 for domain resolution; it is not an IPv6-literal firewall.
The parent must validate the candidate with the installed parser and repeat
domain-based IPv4 egress probes before rollout. No global DNS strategy is changed.

Output: root-only `client-profiles/erg-slot-6.json` under `/opt/xray-reality`,
containing server, port, uuid, public_key, short_id, sni, flow, fingerprint, email.
Transfer privately; never print, attach to tracker, or put in Git. The JSON is an
interchange profile; the migration owner maps it into Proxima's tunnel schema.

The helper validates a protected staged config with the exact installed
`xray run -test -format json -config FILE`, retains a root-only `config.backup-*`, atomically
replaces the config, restarts `xray-reality`, waits two seconds and checks active.
Existing clients, other settings, keys.json and listener port are retained.
Idempotent runs validate but do not restart. **A changed run briefly interrupts
existing exit connections.** Active status is not an end-to-end connectivity
test; the owner must verify existing and new clients before migrating ERG.

All supported client writers take `.client-update.lock`. Do not concurrently run
other config writers. Byte checks reject detected external changes, including
before rollback, but cannot make a non-cooperating writer's check/write atomic.
The normal role never replaces an existing config, preserving all its clients
and settings; intentional config changes require a separately reviewed update.
Fresh installs validate before deploying. No Reality keys are regenerated if
an existing config has lost keys.json: restore the original protected keys.

On failure, the helper restores the exact backup and restarts. If interrupted or
rollback fails, `client-update.pending.json` blocks subsequent provisioning.
After inspecting protected state (without logging secrets), recover on that exit:

```sh
sudo python3 /opt/xray-reality/add-client.py --recover
```

Recovery only restores the recorded backup if its hash matches and current config
is exactly the pre/post transaction bytes. External edits cause a hard stop;
reconcile manually through the authorized infrastructure workflow, never delete
the marker and blindly retry. Retained backups require operator retention policy.
No new profile is emitted until the service restart succeeds.

Offline checks (Linux/WSL; no server, Xray, or network access):

```sh
python3 -B -m unittest discover -s scripts/tests -p test_xray_add_client.py -v
```

Live release gates owned by the parent: exact installed parser, service/listener
health, protected profile transfer, existing-client acceptance and ERG routing.
No commit, push, SSH, live parser or migration was performed by this implementer.
