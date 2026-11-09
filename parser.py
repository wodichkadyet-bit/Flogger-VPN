import base64
import json
import re
import time
import hashlib
from datetime import datetime, timezone, timedelta
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
from urllib.parse import urlparse

# FLOGGER VPN PARSER
# Collection and history stage

ROOT = Path(__file__).parent
SOURCES_FILE = ROOT / "sources.txt"
DATABASE_FILE = ROOT / "servers.json"
SUBSCRIPTION_FILE = ROOT / "subscription.txt"
RESULTS_DIR = ROOT / "results"
STATS_FILE = ROOT / "stats.json"

MAX_SERVERS = 50
MAX_AGE_DAYS = 7

ALLOWED = (
    "vless://",
    "vmess://",
    "trojan://",
    "ss://",
    "hysteria2://",
    "hy2://",
)

HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; FloggerVPN/3.0)"
}


def now():
    return datetime.now(timezone.utc)


def iso(value=None):
    return (value or now()).isoformat()


def parse_date(value):
    try:
        return datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return now()


def read_text(path):
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8", errors="ignore")


def fetch_url(url):
    request = Request(url, headers=HEADERS)
    with urlopen(request, timeout=20) as response:
        return response.read().decode("utf-8", errors="ignore")


def decode_base64(text):
    text = text.strip()
    text += "=" * (-len(text) % 4)

    for decoder in (base64.urlsafe_b64decode, base64.b64decode):
        try:
            return decoder(text).decode("utf-8", errors="ignore")
        except Exception:
            pass

    return ""


def get_source_content(source):
    source = source.strip()

    if not source or source.startswith("#"):
        return ""

    if source.startswith(("http://", "https://")):
        try:
            content = fetch_url(source)

            # Telegram public channel preview
            if "t.me/" in source and "/s/" not in source:
                channel = source.rstrip("/").split("/")[-1]
                content = fetch_url(
                    f"https://t.me/s/{channel}"
                )

            return content

        except Exception as error:
            print(f"[SOURCE ERROR] {source}: {error}")
            return ""

    return source


def extract_links(content):
    found = set()

    # Direct protocol links
    pattern = (
        r'(?i)(?:vless|vmess|trojan|ss|hysteria2|hy2)://'
        r'[^\s<>"\'\]\[{}]+'
    )

    for match in re.findall(pattern, content):
        link = match.rstrip(".,;)")
        if is_allowed(link):
            found.add(link)

    # Base64 subscription content
    for candidate in re.findall(
        r'(?<![A-Za-z0-9+/=_-])[A-Za-z0-9_+/=-]{80,}',
        content
    ):
        decoded = decode_base64(candidate)

        if decoded:
            for match in re.findall(pattern, decoded):
                link = match.rstrip(".,;)")
                if is_allowed(link):
                    found.add(link)

    return found


def is_allowed(link):
    lower = link.lower()

    if lower.startswith(ALLOWED):
        return True

    # Explicitly excluded protocols
    if lower.startswith((
        "wireguard://",
        "socks://",
        "socks4://",
        "socks5://",
        "tuic://",
        "tuicv5://",
    )):
        return False

    return False


def protocol_of(link):
    scheme = link.split("://", 1)[0].lower()

    if scheme == "hy2":
        return "hysteria2"

    if scheme == "ss":
        return "shadowsocks"

    return scheme


def config_id(link):
    return hashlib.sha256(
        link.encode("utf-8")
    ).hexdigest()


def load_database():
    if not DATABASE_FILE.exists():
        return {
            "version": 3,
            "updated": None,
            "servers": []
        }

    try:
        data = json.loads(
            DATABASE_FILE.read_text(encoding="utf-8")
        )

        if not isinstance(data.get("servers"), list):
            data["servers"] = []

        data.setdefault("version", 3)
        data.setdefault("updated", None)

        return data

    except Exception:
        print("[WARNING] servers.json повреждён.")
        return {
            "version": 3,
            "updated": None,
            "servers": []
        }


def save_database(database):
    database["updated"] = iso()

    DATABASE_FILE.write_text(
        json.dumps(
            database,
            ensure_ascii=False,
            indent=2
        ),
        encoding="utf-8"
    )


def main():
    started = time.time()

    print("=" * 45)
    print("       FLOGGER VPN PARSER 3.0")
    print("=" * 45)

    RESULTS_DIR.mkdir(exist_ok=True)

    sources = [
        line.strip()
        for line in read_text(SOURCES_FILE).splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]

    database = load_database()
    servers = database["servers"]

    # Remove records older than seven days
    cutoff = now() - timedelta(days=MAX_AGE_DAYS)

    servers = [
        item for item in servers
        if parse_date(item.get("first_seen")) >= cutoff
    ]

    existing = {
        item["id"]: item
        for item in servers
        if item.get("id")
    }

    discovered = {}

    source_errors = 0

    for source in sources:
        print(f"\n[FETCH] {source}")

        content = get_source_content(source)

        if not content:
            source_errors += 1
            continue

        links = extract_links(content)

        print(f"[FOUND] {len(links)} configurations")

        for link in links:
            discovered[config_id(link)] = link

    new_count = 0

    for identifier, link in discovered.items():
        if identifier in existing:
            item = existing[identifier]
            item["last_seen"] = iso()
        else:
            item = {
                "id": identifier,
                "protocol": protocol_of(link),
                "link": link,
                "first_seen": iso(),
                "last_seen": iso(),
                "last_checked": None,
                "last_success": None,
                "failures": 0,
                "status": "untested"
            }

            servers.append(item)
            existing[identifier] = item
            new_count += 1

    # Sort newest first
    servers.sort(
        key=lambda item: parse_date(item.get("last_seen")),
        reverse=True
    )

    # Keep history, but do not publish untested entries
    database["servers"] = servers
    save_database(database)

    # This stage exports collected configurations.
    # Actual sing-box testing is added in the next stage.
    exportable = [
        item for item in servers
        if item.get("status") == "untested"
        and item.get("link")
    ][:MAX_SERVERS]

    # Protocol files
    protocol_groups = {
        "vless": [],
        "vmess": [],
        "trojan": [],
        "shadowsocks": [],
        "hysteria2": []
    }

    for item in exportable:
        protocol_groups[item["protocol"]].append(item["link"])

    for protocol, links in protocol_groups.items():
        (RESULTS_DIR / f"{protocol}.txt").write_text(
            "\n".join(links),
            encoding="utf-8"
        )

    # Temporary collection output.
    # Do not treat this as a verified working subscription.
    SUBSCRIPTION_FILE.write_text(
        "\n".join(item["link"] for item in exportable),
        encoding="utf-8"
    )

    stats = {
        "updated": iso(),
        "sources": len(sources),
        "found": len(discovered),
        "new": new_count,
        "history": len(servers),
        "subscription": len(exportable),
        "limit": MAX_SERVERS,
        "source_errors": source_errors,
        "testing": "not_enabled_yet",
        "duration_seconds": round(time.time() - started, 2)
    }

    STATS_FILE.write_text(
        json.dumps(stats, ensure_ascii=False, indent=2),
        encoding="utf-8"
    )

    print("\n" + "=" * 45)
    print(f"Sources:       {len(sources)}")
    print(f"Found:         {len(discovered)}")
    print(f"New:           {new_count}")
    print(f"History:       {len(servers)}")
    print(f"Exported:      {len(exportable)} / {MAX_SERVERS}")
    print(f"Source errors: {source_errors}")
    print("Testing:       NOT ENABLED")
    print("=" * 45)


if __name__ == "__main__":
    main()
    
