"""Build and apply one disabled input-chain firewall rule over SSH."""
import ipaddress
import os
import re
import subprocess
import sys
import tempfile


def build_command(action, protocol, port, source, run_id):
    if action not in ("accept", "drop"):
        raise ValueError("action must be accept or drop")
    if protocol not in ("tcp", "udp"):
        raise ValueError("protocol must be tcp or udp")
    if not re.fullmatch(r"[0-9]{1,5}", port) or not 1 <= int(port) <= 65535:
        raise ValueError("port must be in 1..65535")
    network = ipaddress.IPv4Network(source, strict=False)
    if not re.fullmatch(r"[0-9]+", run_id):
        raise ValueError("invalid run id")
    # All interpolated values above have strict allowlists; no free-form RouterOS code.
    return (f'/ip firewall filter add chain=input action={action} protocol={protocol} '
            f'dst-port={int(port)} src-address={network} disabled=yes '
            f'comment="github-actions-{run_id}"')


def main():
    try:
        env = os.environ
        command = build_command(env["INPUT_ACTION"], env["INPUT_PROTOCOL"], env["INPUT_PORT"], env["INPUT_SOURCE"], env["GITHUB_RUN_ID"])
        host, user = env["ROUTER_HOST"], env["ROUTER_USER"]
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}", host):
            raise ValueError("invalid router hostname or IPv4 address")
        if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}", user):
            raise ValueError("invalid SSH username")
        key, known_hosts = env["ROUTER_SSH_KEY"], env["ROUTER_KNOWN_HOSTS"]
        if not key.strip() or not known_hosts.strip():
            raise ValueError("SSH key and pinned host key are required")
        with tempfile.TemporaryDirectory(prefix="routeros-") as directory:
            key_path = os.path.join(directory, "key")
            hosts_path = os.path.join(directory, "known_hosts")
            for path, content in ((key_path, key), (hosts_path, known_hosts)):
                # Exclusive creation with restrictive permissions; temporary directory is private too.
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as file:
                    file.write(content.rstrip() + "\n")
            print("Creating disabled input firewall rule:", command, flush=True)
            result = subprocess.run([
                "ssh", "-T", "-i", key_path, "-o", "BatchMode=yes",
                "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=yes",
                "-o", f"UserKnownHostsFile={hosts_path}", "-o", "GlobalKnownHostsFile=/dev/null",
                "-o", "ConnectTimeout=15", f"{user}@{host}", command,
            ], timeout=45, check=False)
            if result.returncode:
                print(f"SSH failed with exit code {result.returncode}; inspect the router before retrying.", file=sys.stderr)
                return 1
        print("SSH completed. Verify the disabled rule in Winbox before any manual activation.")
        return 0
    except (KeyError, ValueError, OSError, subprocess.TimeoutExpired) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
