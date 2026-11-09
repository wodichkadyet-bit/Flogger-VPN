import base64
import hashlib
import json
import re
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from urllib.request import Request, urlopen

from checker import check_link

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
    "User-Agent": "Mozilla/5.0 (compatible; FloggerVPN/3.1)"
}


def now():
    return datetime.now(timezone.utc)


def iso(value=None):
    return (value or now()).isoformat()


def parse_date(value):
    try:
        result = datetime.fromisoformat(value)
        if result.tzinfo is None:
            result = result.replace(tzinfo=timezone.utc)
        return result
    except (TypeError, ValueError):
        return now()


def read_text(path):
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8", errors="ignore")


def fetch_url(url):
    request = Request(url, headers=HEADERS)
    with urlopen(request, timeout=25) as response:
        return response.read().decode("utf-8", errors="ignore")


def decode_base64(value):
    value = value.strip()
    value += "=" * (-len(value) % 4)

    for decoder in (base64.urlsafe_b64decode, base64.b64decode):
        try:
            return decoder(value).decode("utf-8", errors="ignore")
        except Exception:
            pass

    return ""


def get_source_content(source):
    source = source.strip()

    if not source or source.startswith("#"):
        return ""

    if source.startswith(("http://", "https://")):
        try:
            if "t.me/" in source and "/s/" not in source:
                channel = source.rstrip("/").split("/")[-1]
                url = f"https://t.me/s/{channel}"
                return fetch_url(url)

            return fetch_url(source)

        except Exception as error:
            print(f"[SOURCE ERROR] {source}: {error}")
            return ""

    return source


def is_allowed(link):
    return link.lower().startswith(ALLOWED)


def extract_links(content):
    found = set()

    pattern = (
        r'(?i)(?:vless|vmess|trojan|ss|hysteria2|hy2)://'
        r'[^\s<>"\'\]\[{}]+'
    )

    def add_matches(text):
        for match in re.findall(pattern, text):
            link = match.rstrip(".,;)")
            if is_allowed(link):
                found.add(link)

    add_matches(content)

    # Decode base64 subscription blocks
    candidates = re.findall(
        r'(?<![A-Za-z0-9+/=_-])[A-Za-z0-9_+/=-]{80,}',
        content
    )

    for candidate in candidates:
        decoded = decode_base64(candidate)
        if decoded:
            add_matches(decoded)

    return found


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

    except Exception as error:
        raise RuntimeError(
            f"Cannot read servers.json: {error}"
        )


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


def write_results(exportable):
    RESULTS_DIR.mkdir(exist_ok=True)

    groups = {
        "vless": [],
        "vmess": [],
        "trojan": [],
        "shadowsocks": [],
        "hysteria2": []
    }

    for item in exportable:
        protocol = item.get("protocol")
        link = item.get("link")

        if protocol in groups and link:
            groups[protocol].append(link)

    for protocol, links in groups.items():
        output = RESULTS_DIR / f"{protocol}.txt"
        output.write_text(
            "\n".join(links),
            encoding="utf-8"
        )

    SUBSCRIPTION_FILE.write_text(
        "\n".join(item["link"] for item in exportable),
        encoding="utf-8"
    )


def main():
    started = time.time()

    print("=" * 50)
    print("       FLOGGER VPN PARSER 3.1")
    print("=" * 50)

    RESULTS_DIR.mkdir(exist_ok=True)

    sources = [
        line.strip()
        for line in read_text(SOURCES_FILE).splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]

    database = load_database()
    servers = database["servers"]

    # Remove entries older than seven days
    cutoff = now() - timedelta(days=MAX_AGE_DAYS)

    before_cleanup = len(servers)

    servers = [
        item for item in servers
        if parse_date(item.get("first_seen")) >= cutoff
    ]

    expired_count = before_cleanup - len(servers)

    existing = {
        item["id"]: item
        for item in servers
        if item.get("id")
    }

    discovered = {}
    source_errors = 0

    # Collect configurations
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

    # Add new configurations and refresh last_seen
    for identifier, link in discovered.items():
        if identifier in existing:
            existing[identifier]["last_seen"] = iso()
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

    print("\n[CHECK] Starting sing-box checks")

    working_servers = []
    check_errors = 0
    removed_dead = 0

    # Check every configuration in the database
    for index, item in enumerate(servers, start=1):
        link = item.get("link", "")

        if not link:
            continue

        print(
            f"\n[CHECK {index}/{len(servers)}] "
            f"{item.get('protocol', 'unknown')}"
        )

        try:
            result = check_link(link)

        except Exception as error:
            result = {
                "cloudflare": False,
                "google": False,
                "working": False,
                "error": str(error)[:250]
            }

        item["last_checked"] = iso()
        item["cloudflare"] = bool(result.get("cloudflare"))
        item["google"] = bool(result.get("google"))

        if result.get("working"):
            item["status"] = "working"
            item["last_success"] = iso()
            item["failures"] = 0
            item.pop("check_error", None)

            working_servers.append(item)

            print(
                "[WORKING] "
                f"Cloudflare={item['cloudflare']} "
                f"Google={item['google']}"
            )

        elif result.get("error"):
            item["status"] = "check_error"
            item["check_error"] = str(result["error"])[:250]
            check_errors += 1

            print(f"[CHECK ERROR] {item['check_error']}")

        else:
            # Both external tests failed
            item["status"] = "dead"
            item["failures"] = item.get("failures", 0) + 1
            removed_dead += 1

            print("[DEAD] Both tests failed")

    # Permanently remove servers that failed both tests
    servers = [
        item for item in servers
        if item.get("status") != "dead"
    ]

    # Sort by most recent successful check
    working_servers.sort(
        key=lambda item: parse_date(item.get("last_success")),
        reverse=True
    )

    # Maximum 50 verified configurations
    exportable = working_servers[:MAX_SERVERS]

    # Save database and subscription
    database["servers"] = servers
    save_database(database)

    write_results(exportable)

    stats = {
        "version": "3.1",
        "updated": iso(),
        "sources": len(sources),
        "source_errors": source_errors,
        "found": len(discovered),
        "new": new_count,
        "history": len(servers),
        "expired": expired_count,
        "checked": len(servers),
        "working": len(working_servers),
        "subscription": len(exportable),
        "limit": MAX_SERVERS,
        "removed_dead": removed_dead,
        "check_errors": check_errors,
        "testing": "sing-box",
        "tests": [
            "cloudflare",
            "google"
        ],
        "duration_seconds": round(
            time.time() - started, 2
        )
    }

    STATS_FILE.write_text(
        json.dumps(
            stats,
            ensure_ascii=False,
            indent=2
        ),
        encoding="utf-8"
    )

    print("\n" + "=" * 50)
    print("       FLOGGER VPN RESULTS")
    print("=" * 50)
    print(f"Sources:       {len(sources)}")
    print(f"Found:         {len(discovered)}")
    print(f"New:           {new_count}")
    print(f"Working:       {len(working_servers)}")
    print(f"Exported:      {len(exportable)} / {MAX_SERVERS}")
    print(f"Removed dead:  {removed_dead}")
    print(f"Expired:       {expired_count}")
    print(f"Check errors:  {check_errors}")
    print(f"Source errors: {source_errors}")
    print(f"Duration:      {stats['duration_seconds']} sec")
    print("=" * 50)


if __name__ == "__main__":
    main()
    
