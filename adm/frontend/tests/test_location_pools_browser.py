"""Browser contract test against a built local preview; all API calls are fixtures.

Run a preview on localhost:4178, then pytest this file. Requires Playwright and Edge.
"""
import json
import re
from pathlib import Path

import pytest
from playwright.sync_api import expect, sync_playwright


@pytest.mark.parametrize("language", ["en", "tr", "ru"])
def test_admin_creates_reorders_and_explicitly_grants_pool(language, tmp_path):
    text = json.loads((Path(__file__).parents[1] / "src/locales" / f"{language}.json").read_text(encoding="utf-8"))
    pools, writes = [], []
    inventory = {
        str(i): {"server_name": name, "server_display_name": name, "routes": [
            {"route_id": slot, "label": label, "kind": "full_tunnel", "enabled": True,
             "available": True, "stale": False}]}
        for i, name, slot, label in ((1, "SHV", "slot-pl", "Poland AWG"), (2, "SVR", "slot-de", "Germany VLESS"))
    }

    def answer(route):
        request = route.request
        path = request.url.split("/api", 1)[1]
        payload = None
        if request.method in ("POST", "PUT"):
            payload = request.post_data_json
            writes.append((path, payload))
        if path == "/auth/me":
            data = {"auth_configured": True, "username": "fixture-admin", "role": "superadmin"}
        elif path == "/servers":
            data = []
        elif path == "/vpn-servers/profiles":
            data = inventory
        elif path == "/vpn-users":
            data = [{"id": 1, "username": "alice", "enabled": True, "allow_pools": False}]
        elif path == "/pool-catalog" and request.method == "POST":
            data = {**payload, "id": "fixture-pool", "policy_revision": 1, "user_ids": []}
            pools.append(data)
        elif path == "/pool-catalog":
            data = pools
        elif path == "/pool-catalog/fixture-pool/users/1":
            pools[0]["user_ids"] = [1] if payload["enabled"] else []
            data = payload
        else:
            raise AssertionError(f"Unexpected fixture request: {request.method} {path}")
        route.fulfill(json={"ok": True, "data": data})

    with sync_playwright() as p:
        browser = p.chromium.launch(channel="msedge")
        page = browser.new_page(viewport={"width": 1100, "height": 850})
        page.set_default_timeout(5000)
        errors = []
        page.on("pageerror", lambda error: errors.append(str(error)))
        page.add_init_script("localStorage.setItem('adm_token','fixture'); localStorage.setItem('adm_dashboard_tab','4');"
                             f"localStorage.setItem('adm_lang', {json.dumps(language)});")
        page.route("**/api/**", answer)
        page.goto("http://127.0.0.1:4178/")
        page.get_by_role("button", name=text["pools"]["create"], exact=True).click()
        dialog = page.get_by_role("dialog")
        dialog.get_by_label(text["pools"]["label"], exact=True).fill("EU")
        assert dialog.get_by_role("combobox", name=text["pools"]["site"], exact=True).count() == 1, dialog.aria_snapshot()
        for name, label in (("SHV", "Poland AWG"), ("SVR", "Germany VLESS")):
            dialog.get_by_role("combobox", name=re.compile("^" + re.escape(text["pools"]["site"]) + r"(?:\s|$)")).click()
            page.get_by_role("option", name=name, exact=True).click()
            dialog.get_by_role("combobox", name=re.compile("^" + re.escape(text["pools"]["route"]) + r"(?:\s|$)")).click()
            page.get_by_role("option", name=label, exact=True).click()
            dialog.get_by_role("button", name=text["pools"]["addMember"], exact=True).click()
        dialog.get_by_role("button", name=text["pools"]["up"], exact=True).nth(1).click()
        dialog.get_by_role("checkbox", name=text["pools"]["enabled"], exact=True).check()
        dialog.get_by_role("button", name=text["common.save"], exact=True).click()
        expect(page.get_by_role("heading", name="EU", exact=True)).to_be_visible()
        assert writes[0][1] == {"schema_version": 2, "label": "EU", "kind": "full_tunnel", "enabled": True,
                                "members": [{"site_id": 2, "route_id": "slot-de"}, {"site_id": 1, "route_id": "slot-pl"}]}
        page.get_by_role("button", name=text["pools"]["grants"], exact=True).click()
        expect(page.get_by_text(text["pools"]["prerequisite"], exact=True)).to_be_visible()
        page.get_by_role("dialog").get_by_role("checkbox").click()
        expect(page.get_by_role("dialog").get_by_role("checkbox")).to_be_checked()
        assert writes[-1] == ("/pool-catalog/fixture-pool/users/1", {"enabled": True})
        assert all("allow_pools" not in body for _, body in writes)
        page.screenshot(path=str(tmp_path / f"pools-{language}.png"))
        assert not errors
        browser.close()
