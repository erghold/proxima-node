"""The deploy must carry the revision that was pushed, not the one that happened
to be in the checkout.

ADM ran as root while the checkout belonged to the user whose SSH key GitHub
accepts, so the source refresh failed with "Could not read from remote
repository" — and the deploy continued with whatever the checkout held. The
operation was recorded as a success and the site came up on last week's
revision. It bit twice in one session (2026-10-20, operations 111 and 114 on
SVR), and the only evidence of what a deploy carried was the site's
version.json.
"""

import subprocess

from core import vpn_provision


def _fake_run(calls, fail=False):
    def run(cmd, **kwargs):
        calls.append(cmd)
        if fail:
            raise subprocess.CalledProcessError(128, cmd, stderr="Permission denied (publickey).")
        return subprocess.CompletedProcess(cmd, 0, stdout="abc1234\n1700000000\n")
    return run


def test_git_runs_as_the_owner_of_the_checkout(monkeypatch):
    """Root has no GitHub key of its own; the checkout owner's do."""
    calls = []
    monkeypatch.setattr(vpn_provision, "_git_as_checkout_owner",
                        lambda: ["runuser", "-u", "can", "--"])
    monkeypatch.setattr(vpn_provision.subprocess, "run", _fake_run(calls))
    monkeypatch.setattr(vpn_provision, "source_revision",
                        lambda: {"commit": "abc1234", "short": "abc1234", "committed_at": 1})

    revision, error = vpn_provision.update_source()

    assert error is None
    assert revision["short"] == "abc1234"
    assert calls[0][:5] == ["runuser", "-u", "can", "--", "git"], calls[0]
    assert calls[1][:5] == ["runuser", "-u", "can", "--", "git"], calls[1]


def test_a_failed_refresh_is_reported_and_raises_nothing(monkeypatch):
    calls = []
    monkeypatch.setattr(vpn_provision, "_git_as_checkout_owner", lambda: [])
    monkeypatch.setattr(vpn_provision.subprocess, "run", _fake_run(calls, fail=True))

    revision, error = vpn_provision.update_source()

    assert revision is None
    assert error and "Could not update the source checkout" in error
    assert "publickey" in error


def test_without_root_the_prefix_is_empty(monkeypatch):
    """A developer machine has its own credentials; the prefix is only needed
    when the service runs as root."""
    monkeypatch.setattr(vpn_provision.os, "geteuid", lambda: 1000, raising=False)
    assert vpn_provision._git_as_checkout_owner() == []
