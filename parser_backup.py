import re
import json
import time
import base64
import html
import os
from collections import Counter
from urllib.request import Request, urlopen
from urllib.parse import urlparse
from html.parser import HTMLParser
from datetime import datetime, timezone

PROJECT = "Flogger VPN"
TIMEOUT = 12
MAX_BYTES = 2_000_000

PROTOCOLS = {
    "vless": ["vless"],
    "vmess": ["vmess"],
    "trojan": ["trojan"],
    "shadowsocks": ["ss", "ssr"],
    "socks": ["socks4", "socks4a", "socks5", "socks5h"],
    "hysteria2": ["hysteria2", "hy2"],
    "tuic": ["tuic"],
}

SCHEMES = [
    scheme
    for schemes in PROTOCOLS.values()
    for scheme in schemes
]

class TextParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.parts = []

    def handle_data(self, data):
        self.parts.append(data)

    def get_text(self):
        return "\n".join(self.parts)


def read_sources():
    if not os.path.exists("sources.txt"):
        raise FileNotFoundError("sources.txt not found")

    with open("sources.txt", encoding="utf-8") as f:
        return [
            line.strip()
            for line in f
            if line.strip() and not line.strip().startswith("#")
        ]


def fetch_source(url):
    # Public Telegram channel preview
    match = re.match(
        r"https?://t\.me/(?:s/)?([A-Za-z0-9_]+)",
        url
    )

    if match:
        channel = match.group(1)
        url = f"https://t.me/s/{channel}"

    request = Request(
        url,
        headers={"User-Agent": "Mozilla/5.0 FloggerParser/2.0"}
    )

    with urlopen(request, timeout=TIMEOUT) as response:
        data = response.read(MAX_BYTES + 1)

    if len(data) > MAX_BYTES:
        data = data[:MAX_BYTES]

    raw = data.decode("utf-8", errors="replace")
    parser = TextParser()
    parser.feed(raw)

    return html.unescape(raw + "\n" + parser.get_text())


def decode_base64(text):
    """Try decoding long base64 strings found in subscriptions."""
    results = []

    for token in re.findall(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{80,}={0,2}", text):
        try:
            padded = token + "=" * (-len(token) % 4)
            decoded = base64.b64decode(
                padded, validate=True
            ).decode("utf-8", errors="ignore")

            if "://" in decoded:
                results.append(decoded)
        except Exception:
            continue

    return "\n".join(results)


def extract_links(text):
    found = set()

    # Standard VPN and proxy URI formats
    schemes = "|".join(SCHEMES)

    pattern = re.compile(
        rf"(?i)(?:{schemes})://[^\s<>\"']+"
    )

    for match in pattern.findall(text):
        link = match.rstrip(".,;)]}，。")
        found.add(link)

    # HTTP/HTTPS proxies: accept only explicit credentials.
    http_pattern = re.compile(
        r"https?://[^/\s:@]+:[^/\s@]+@"
        r"[A-Za-z0-9.-]+:\d{2,5}(?:/[^\s]*)?",
        re.I
    )

    for match in http_pattern.findall(text):
        found.add(match.rstrip(".,;)]}"))

    return found


def get_protocol(link):
    scheme = link.split("://", 1)[0].lower()

    for protocol, schemes in PROTOCOLS.items():
        if scheme in schemes:
            return protocol

    if scheme in ("http", "https"):
        return "http_proxy"

    return "unknown"


def find_wireguard(text):
    # Detect WireGuard blocks, but do not publish private keys.
    blocks = re.findall(
        r"(?ims)^\[Interface\].*?(?=^\[Interface\]|\Z)",
        text
    )

    return sum(
        1 for block in blocks
        if "PrivateKey" in block and "[Peer]" in block
    )


def main():
    started = time.time()
    sources = read_sources()

    all_links = set()
    errors = []
    wireguard_found = 0

    print(f"=== {PROJECT} 2.0 ===", flush=True)
    print(f"Sources: {len(sources)}", flush=True)

    for index, source in enumerate(sources, 1):
        print(
            f"[{index}/{len(sources)}] Reading {source}",
            flush=True
        )

        try:
            content = fetch_source(source)

            decoded = decode_base64(content)
            content += "\n" + decoded

            links = extract_links(content)
            wg_count = find_wireguard(content)

            wireguard_found += wg_count
            before = len(all_links)
            all_links.update(links)

            print(
                f"Found: {len(links)} | "
                f"New unique: {len(all_links) - before} | "
                f"WireGuard detected: {wg_count}",
                flush=True
            )

        except Exception as error:
            errors.append({
                "source": source,
                "error": str(error)[:250]
            })
            print(f"Source error: {error}", flush=True)

    counts = Counter(get_protocol(link) for link in all_links)

    os.makedirs("results", exist_ok=True)

    # Main subscription
    with open("subscription.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(sorted(all_links)))
        if all_links:
            f.write("\n")

    # Separate files for each protocol
    for protocol in list(PROTOCOLS) + ["http_proxy"]:
        selected = [
            link for link in sorted(all_links)
            if get_protocol(link) == protocol
        ]

        filename = f"results/{protocol}.txt"

        with open(filename, "w", encoding="utf-8") as f:
            f.write("\n".join(selected))
            if selected:
                f.write("\n")

    stats = {
        "project": PROJECT,
        "version": "2.0",
        "updated": datetime.now(timezone.utc).isoformat(),
        "sources_total": len(sources),
        "source_errors": len(errors),
        "found": len(all_links),
        "saved": len(all_links),
        "wireguard_detected": wireguard_found,
        "protocols": dict(counts),
        "errors": errors,
        "duration_seconds": round(time.time() - started, 2)
    }

    with open("stats.json", "w", encoding="utf-8") as f:
        json.dump(stats, f, indent=2, ensure_ascii=False)

    print("\n=== FINISHED ===", flush=True)
    print(f"Unique links: {len(all_links)}", flush=True)
    print(f"WireGuard blocks detected: {wireguard_found}", flush=True)
    print(f"Source errors: {len(errors)}", flush=True)
    print(f"Duration: {stats['duration_seconds']} seconds", flush=True)


if __name__ == "__main__":
    main()
    
