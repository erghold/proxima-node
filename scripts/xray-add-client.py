#!/usr/bin/env python3
"""Add one ERG identity to an existing Reality listener; never print secrets."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time
import uuid


def digest(data):
    return hashlib.sha256(data).hexdigest()


def encode(value):
    return (json.dumps(value, indent=2) + "\n").encode()


def read(path):
    if path.is_symlink() or not path.is_file():
        raise ValueError("Required regular file missing or symlinked")
    return path.read_bytes()


def private_file(directory, data, prefix):
    fd, name = tempfile.mkstemp(dir=directory, prefix=prefix)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    return Path(name)


def sync_dir(directory):
    fd = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def replace(path, data):
    staged = private_file(path.parent, data, ".stage-")
    try:
        os.replace(staged, path)
        sync_dir(path.parent)
    finally:
        staged.unlink(missing_ok=True)


def run(argv):
    # Xray diagnostics can echo credentials from a rejected configuration.
    subprocess.run(argv, check=True, stdout=subprocess.DEVNULL,
                   stderr=subprocess.DEVNULL, timeout=45)


def restart():
    run(["systemctl", "restart", "xray-reality"])
    time.sleep(2)
    run(["systemctl", "is-active", "--quiet", "xray-reality"])


def plan(raw, keys_raw, label, server):
    config = json.loads(raw)
    keys = json.loads(keys_raw)
    matches = [i for i in config["inbounds"] if i.get("protocol") == "vless"
               and i.get("streamSettings", {}).get("security") == "reality"]
    if len(matches) != 1:
        raise ValueError("Exactly one Reality VLESS inbound required")
    inbound = matches[0]
    stream = inbound["streamSettings"]
    reality = stream["realitySettings"]
    if stream.get("network") not in ("tcp", "raw"):
        raise ValueError("Only TCP Reality supported")
    if (keys["private_key"] != reality["privateKey"] or not keys["public_key"]
            or keys["short_id"] not in reality["shortIds"]):
        raise ValueError("Reality keys disagree with current configuration")
    clients = inbound["settings"]["clients"]
    if not isinstance(clients, list) or not clients:
        raise ValueError("Existing clients required")
    ids = [str(uuid.UUID(c["id"])) for c in clients]
    labels = [c["email"] for c in clients if c.get("email")]
    if len(ids) != len(set(ids)) or len(labels) != len(set(labels)):
        raise ValueError("Duplicate client identity or label")
    existing = next((c for c in clients if c.get("email") == label), None)
    if existing and existing.get("flow") != "xtls-rprx-vision":
        raise ValueError("Existing label has incompatible flow")
    client = existing or {"id": str(uuid.uuid4()), "email": label,
                          "flow": "xtls-rprx-vision"}
    if not existing:
        clients.append(client)
    profile = {"server": server, "port": inbound["port"], "uuid": client["id"],
               "public_key": keys["public_key"], "short_id": keys["short_id"],
               "sni": reality["serverNames"][0], "flow": client["flow"],
               "fingerprint": "chrome", "email": label}
    return (encode(config) if not existing else raw), profile


def recover(directory, restart_service=restart):
    marker = directory / "client-update.pending.json"
    state = json.loads(read(marker))
    backup = directory / state["backup"]
    if backup.parent != directory or not backup.name.startswith("config.backup-"):
        raise ValueError("Invalid recovery backup")
    old = read(backup)
    current = read(directory / "config.json")
    if digest(old) != state["before"] or digest(current) not in (state["before"], state["after"]):
        raise ValueError("External config edit; recovery refused")
    replace(directory / "config.json", old)
    restart_service()
    marker.unlink()
    sync_dir(directory)


def provision(directory, label, server, validator=run, restart_service=restart):
    config_path = directory / "config.json"
    keys_path = directory / "keys.json"
    marker = directory / "client-update.pending.json"
    if marker.exists():
        raise ValueError("Pending transaction: inspect and use --recover first")
    old, keys = read(config_path), read(keys_path)
    candidate, profile = plan(old, keys, label, server)
    profiles = directory / "client-profiles"
    if profiles.is_symlink():
        raise ValueError("Profile directory must not be a symlink")
    profiles.mkdir(mode=0o700, exist_ok=True)
    os.chmod(profiles, 0o700)
    output = profiles / (label + ".json")
    if output.exists() or output.is_symlink():
        if json.loads(read(output)) != profile:
            raise ValueError("Existing profile conflicts; refusing replacement")
        os.chmod(output, 0o600)
    staged = private_file(directory, candidate, ".candidate-")
    try:
        validator([str(directory / "xray"), "run", "-test", "-format", "json", "-config", str(staged)])
        if read(config_path) != old or read(keys_path) != keys:
            raise ValueError("External edit detected before deployment")
        if candidate != old:
            backup = private_file(directory, old, "config.backup-")
            replace(marker, encode({"backup": backup.name, "before": digest(old),
                                    "after": digest(candidate)}))
            try:
                if read(config_path) != old or read(keys_path) != keys:
                    raise ValueError("External edit detected before replacement")
                os.replace(staged, config_path)
                sync_dir(directory)
                restart_service()
                if read(config_path) != candidate or read(keys_path) != keys:
                    raise ValueError("External edit detected after restart")
            except Exception:
                recover(directory, restart_service)
                raise
            marker.unlink()
            sync_dir(directory)
        if not output.exists():
            replace(output, encode(profile))
        return candidate != old
    finally:
        staged.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, default=Path("/opt/xray-reality"))
    parser.add_argument("--label")
    parser.add_argument("--server")
    parser.add_argument("--recover", action="store_true")
    args = parser.parse_args()
    if not args.recover and (not re.fullmatch(r"erg-slot-[1-9][0-9]*", args.label or "")
                             or not re.fullmatch(r"[A-Za-z0-9.:-]+", args.server or "")):
        parser.error("--label erg-slot-N and --server hostname/IP required")
    if os.geteuid() != 0 or args.directory.is_symlink():
        parser.error("Root and a real installation directory required")
    import fcntl
    os.umask(0o077)
    directory = args.directory.resolve(strict=True)
    # All supported writers must share this lock; byte checks detect other edits.
    with open(directory / ".client-update.lock", "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if args.recover:
            recover(directory)
            print("recovered")
        else:
            print("changed" if provision(directory, args.label, args.server) else "unchanged")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        # No exception values: parser/subprocess errors may contain credentials.
        raise SystemExit("Client provisioning failed; inspect protected state and pending recovery marker")
