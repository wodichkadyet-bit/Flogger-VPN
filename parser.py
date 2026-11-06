
import re
import json
import socket
import uuid
import urllib.request
from urllib.parse import urlsplit
from datetime import datetime, timezone
from pathlib import Path

TIMEOUT = 3
SOURCES_FILE = "sources.txt"

def download_source(url):
    try:
        request = urllib.request.Request(
            url,
            headers={"User-Agent": "FloggerVPN-Parser/1.0"}
        )
        with urllib.request.urlopen(request, timeout=15) as response:
            return response.read().decode("utf-8", errors="ignore")
    except Exception as error:
        print(f"[SOURCE ERROR] {url}: {error}")
        return ""

def extract_configs(text):
    return re.findall(r"vless://[^\s\"'<>]+", text)

def validate_config(config):
    try:
        parsed = urlsplit(config)

        if parsed.scheme != "vless":
            return False, "Invalid scheme"

        uuid.UUID(parsed.username or "")

        host = parsed.hostname
        port = parsed.port

        if not host or not port or not (1 <= port <= 65535):
            return False, "Invalid address or port"

        return True, (host, port)

    except Exception:
        return False, "Invalid configuration"

def check_tcp(host, port):
    try:
        with socket.create_connection(
            (host, port), timeout=TIMEOUT
        ):
            return True
    except OSError:
        return False

def main():
    sources = Path(SOURCES_FILE)

    if not sources.exists():
        print("sources.txt not found")
        return

    urls = [
        line.strip()
        for line in sources.read_text().splitlines()
        if line.strip().startswith("https://")
    ]

    configs = set()
    source_errors = 0

    for url in urls:
        print(f"[SOURCE] {url}")
        content = download_source(url)

        if not content:
            source_errors += 1

        configs.update(extract_configs(content))

    valid = []
    reachable = 0
    invalid = 0

    for config in sorted(configs):
        ok, result = validate_config(config)

        if not ok:
            invalid += 1
            continue

        host, port = result

        if check_tcp(host, port):
            valid.append(config)
            reachable += 1

    Path("subscription.txt").write_text(
        "\n".join(valid) + ("\n" if valid else ""),
        encoding="utf-8"
    )

    stats = {
        "project": "Flogger VPN",
        "updated": datetime.now(timezone.utc).isoformat(),
        "found": len(configs),
        "tcp_reachable": reachable,
        "invalid": invalid,
        "source_errors": source_errors,
        "saved": len(valid)
    }

    Path("stats.json").write_text(
        json.dumps(stats, indent=2, ensure_ascii=False),
        encoding="utf-8"
    )

    print(json.dumps(stats, indent=2))
    print("[FLOGGER] Parsing completed!")

if __name__ == "__main__":
    main()
  
