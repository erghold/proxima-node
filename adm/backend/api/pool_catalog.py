"""Explicit, immutable pool semantics; every member is currently unavailable."""

import ipaddress
import json
import uuid

from flask import Blueprint

from api.pool_client import bp as client_bp, body, error, result, session
from core.pool_authorization import COMBINATIONS, authorized_manifest
from core.authz import superadmin_only
from core.pool_db import transaction
from core import location_pools

bp = Blueprint("pool_catalog", __name__)
COUNTRIES = set("AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW".split())


def new_id():
    return str(uuid.uuid4())


def definition(conn, data):
    if set(data) - {"label", "exit_country", "routing_mode", "resources", "members"}:
        raise ValueError("unknown_pool_field")
    label, mode, country = data.get("label"), data.get("routing_mode"), data.get("exit_country")
    if not isinstance(label, str) or not label.strip() or len(label) > 100:
        raise ValueError("invalid_label")
    if mode not in ("fast", "lan_only") or (mode == "fast" and (not isinstance(country, str) or country not in COUNTRIES)) or (mode == "lan_only" and country is not None):
        raise ValueError("invalid_country_or_mode")
    resources, members = data.get("resources", []), data.get("members", [])
    if not isinstance(resources, list) or len(resources) > 32 or not isinstance(members, list) or not 1 <= len(members) <= 16:
        raise ValueError("invalid_pool_size")
    output_resources, output_members = [], []
    for resource in resources:
        if not isinstance(resource, dict) or set(resource) != {"site_id", "cidrs"} or type(resource["site_id"]) is not int:
            raise ValueError("invalid_resource")
        site = conn.execute("SELECT * FROM vpn_servers WHERE id=?", (resource["site_id"],)).fetchone()
        cidrs = resource["cidrs"]
        if not site or not site["lan_subnet"] or not isinstance(cidrs, list) or not 1 <= len(cidrs) <= 16:
            raise ValueError("invalid_resource_scope")
        network = ipaddress.ip_network(site["lan_subnet"])
        for cidr in cidrs:
            if not isinstance(cidr, str) or not ipaddress.ip_network(cidr).subnet_of(network):
                raise ValueError("resource_outside_site_lan")
        output_resources.append({"id": new_id(), "site_id": site["id"], "cidrs": cidrs})
    for member in members:
        if not isinstance(member, dict) or set(member) != {"site_id", "bindings"} or type(member["site_id"]) is not int:
            raise ValueError("invalid_member")
        if not conn.execute("SELECT 1 FROM vpn_servers WHERE id=?", (member["site_id"],)).fetchone():
            raise ValueError("unknown_site")
        bindings = member["bindings"]
        if not isinstance(bindings, list) or not 1 <= len(bindings) <= 8:
            raise ValueError("invalid_bindings")
        output = []
        for binding in bindings:
            if not isinstance(binding, dict) or set(binding) != {"connection_type", "routing_mode", "profile_format"}:
                raise ValueError("invalid_binding")
            combo = tuple(binding[k] for k in ("connection_type", "routing_mode", "profile_format"))
            if not all(isinstance(v, str) for v in combo) or combo not in COMBINATIONS or binding["routing_mode"] != mode:
                raise ValueError("unsupported_binding_combination")
            output.append({"id": new_id(), **binding})
        output_members.append({"id": new_id(), "site_id": member["site_id"], "bindings": output,
                               "eligible": False, "reason": "attachment_not_provisioned",
                               "equivalence_revision": None})
    return {"id": new_id(), "label": label, "policy_revision": new_id(), "exit_country": country,
            "routing_modes": [mode], "internet_bypass": "none" if mode == "fast" else "unmanaged",
            "local_lan": "preserve", "lan_resource_set": {"id": new_id(), "revision": new_id(), "resources": output_resources},
            "members": output_members}


@bp.get("/api/pool-catalog")
@superadmin_only
def catalog():
    with transaction() as conn:
        return result([{**json.loads(r["definition"]), "enabled": bool(r["enabled"]),
                        "user_ids": [u[0] for u in conn.execute("SELECT u.id FROM vpn_users u JOIN pool_grants g ON g.account_id=u.account_id WHERE g.pool_id=?", (r["id"],))]}
                       for r in conn.execute("SELECT * FROM pool_catalog ORDER BY id")])


@bp.post("/api/pool-catalog")
@superadmin_only
def create():
    with transaction() as conn:
        try:
            data = body()
            pool = location_pools.definition(conn, data) if "schema_version" in data else definition(conn, data)
        except (ValueError, TypeError) as exc:
            return error(str(exc), 400)
        enabled = data.get("enabled", True)
        conn.execute("INSERT INTO pool_catalog(id,definition,enabled) VALUES (?,?,?)", (pool["id"], json.dumps(pool), int(enabled)))
    return result({**pool, "enabled": enabled} if pool.get("schema_version") == 2 else pool, 201)


@bp.put("/api/pool-catalog/<pool_id>")
@superadmin_only
def update(pool_id):
    data = body()
    with transaction() as conn:
        row = conn.execute("SELECT * FROM pool_catalog WHERE id=?", (pool_id,)).fetchone()
        if not row:
            return error("pool_not_found", 404)
        previous = json.loads(row["definition"])
        if previous.get("schema_version") == 2:
            if type(data.get("schema_version")) is not int or data.get("schema_version") != 2:
                return error("schema_version_required", 400)
            if type(data.get("policy_revision")) is not int or data.get("policy_revision") != previous["policy_revision"]:
                return error("policy_revision_conflict", 409)
            try:
                pool = location_pools.definition(conn, data, previous)
            except (ValueError, TypeError) as exc:
                return error(str(exc), 400)
            conn.execute("UPDATE pool_catalog SET definition=?,enabled=? WHERE id=?", (json.dumps(pool), int(data["enabled"]), pool_id))
            return result({**pool, "enabled": data["enabled"]})
        if previous.get("schema_version", 1) != 1 or set(data) != {"enabled"} or type(data["enabled"]) is not bool:
            return error("immutable_pool_semantics_create_new_pool", 400)
        if not conn.execute("UPDATE pool_catalog SET enabled=? WHERE id=?", (int(data["enabled"]), pool_id)).rowcount:
            return error("pool_not_found", 404)
    return result({"enabled": data["enabled"]})


@bp.put("/api/pool-catalog/<pool_id>/users/<int:user_id>")
@superadmin_only
def grant(pool_id, user_id):
    data = body()
    if set(data) != {"enabled"} or type(data["enabled"]) is not bool:
        return error("enabled_must_be_boolean", 400)
    with transaction() as conn:
        user = conn.execute("SELECT * FROM vpn_users WHERE id=?", (user_id,)).fetchone()
        row = conn.execute("SELECT definition FROM pool_catalog WHERE id=?", (pool_id,)).fetchone()
        if not user or not row:
            return error("not_found", 404)
        version = json.loads(row["definition"]).get("schema_version", 1)
        if type(version) is not int or version not in (1, 2):
            return error("unsupported_schema_version", 400)
        if data["enabled"] and (not user["enabled"] or dict(user).get("deletion_pending")):
            return error("account_not_available", 409)
        if data["enabled"]:
            conn.execute("INSERT OR IGNORE INTO pool_grants VALUES (?,?)", (pool_id, user["account_id"]))
        else:
            conn.execute("DELETE FROM pool_grants WHERE pool_id=? AND account_id=?", (pool_id, user["account_id"]))
    return result({"enabled": data["enabled"]})


@client_bp.get("/api/vpn/pools")
def manifest():
    with transaction() as conn:
        auth, user = session(conn)
        if not auth:
            return error("unauthorized", 401)
        data, _ = authorized_manifest(conn, user)
        return result(data)
