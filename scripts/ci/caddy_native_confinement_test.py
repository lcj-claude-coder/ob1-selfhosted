#!/usr/bin/env python3
"""Exercise the shipped proxy inside an isolated, network-free Caddy container.

An extra loopback-only echo listener observes exactly what the upstream receives.
Only a staged Caddyfile is mounted; deployment env files never enter the fixture.
Companion server/DB tests verify auth decisions, audit reasons and memory RLS.
"""
from pathlib import Path
import os
import re
import subprocess
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parents[2]


def run(*args, check=True):
    return subprocess.run(args, text=True, capture_output=True, check=check, timeout=30)


def main():
    dockerfile = (ROOT / "deploy/compose-tailnet/caddy/Dockerfile").read_text()
    match = re.search(r"^FROM (caddy:[0-9]+\.[0-9]+\.[0-9]+[A-Za-z0-9._-]*)$", dockerfile, re.M)
    if not match:
        raise RuntimeError("expected an official patch-pinned Caddy image")
    container = "ob1-proxy-test-" + uuid.uuid4().hex
    image = match[1]
    scratch = Path(os.environ.get("TMPDIR", tempfile.gettempdir())) / f"ob1-tests-{os.getuid()}"
    scratch.mkdir(mode=0o700, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="proxy-", dir=scratch) as directory:
        config = Path(directory) / "Caddyfile"
        config.write_text((ROOT / "deploy/compose-tailnet/Caddyfile").read_text() + '''
:18787 {
    bind 127.0.0.1
    respond "key={http.request.header.X-Brain-Key}|marker={http.request.header.X-OpenBrain-Tailnet}|auth={http.request.header.Authorization}"
}
''')
        try:
            run("docker", "run", "-d", "--name", container, "--network", "none",
                "--read-only", "--cap-drop", "ALL", "--cap-add", "NET_BIND_SERVICE", "--security-opt", "no-new-privileges",
                "--tmpfs", "/data", "--tmpfs", "/config", "--tmpfs", "/var/log/caddy",
                "-e", "MCP_UPSTREAM=127.0.0.1:18787",
                "-v", f"{config}:/etc/caddy/Caddyfile:ro,z", image)

            def request(headers=(), path="/mcp", check=True):
                args = ["docker", "exec", container, "wget", "-q", "-S", "-O", "-", "-T", "5"]
                for header in headers:
                    args.extend(["--header", header])
                return run(*args, f"http://127.0.0.1:9787{path}", check=check)

            for _ in range(40):
                if request(path="/caddy-health", check=False).returncode == 0:
                    break
                time.sleep(0.1)
            else:
                raise RuntimeError("Caddy did not become ready")

            native = "fixture-native-key"
            bearer = "Bearer fixture-oauth"
            base = [f"X-Brain-Key: {native}", f"Authorization: {bearer}"]
            for marker in [None, "spoofed", "1", "1, 1"]:
                headers = base + ([] if marker is None else [f"X-OpenBrain-Tailnet: {marker}"])
                assert request(headers).stdout == f"key={native}|marker=1|auth={bearer}", "tailnet must replace caller marker and preserve credentials"
            for funnel in ["?1", "unexpected", ""]:
                headers = base + ["x-openbrain-tailnet: 1", f"tailscale-funnel-request: {funnel}", "X-Forwarded-For: 160.79.104.5"]
                assert request(headers).stdout == f"key=|marker=|auth={bearer}", "public branch must strip key and marker, preserving OAuth"
                for path in ["/ready", "/api/v1/thoughts"]:
                    denied = request(headers, path, check=False)
                    assert denied.returncode != 0 and "404" in denied.stderr, "private routes must stay unavailable publicly"
            denied = request(base + ["Tailscale-Funnel-Request: ?1", "X-Forwarded-For: 203.0.113.1"], check=False)
            assert denied.returncode != 0 and "403" in denied.stderr, "public IP perimeter must remain enforced"
            logs = run("docker", "exec", container, "cat", "/var/log/caddy/funnel-access.log", "/var/log/caddy/tailnet-access.log").stdout
            assert native not in logs and bearer not in logs, "credentials must not appear in access logs"
            print("Caddy confinement passed: tailnet marker replacement, public strip, OAuth forwarding, private routes, IP perimeter, log redaction")
        except Exception:
            # Fixture-only diagnostics: no real tokens, env files, or services.
            print(run("docker", "logs", container, check=False).stderr[-4000:])
            raise
        finally:
            run("docker", "rm", "-f", "-v", container, check=False)


if __name__ == "__main__":
    main()
