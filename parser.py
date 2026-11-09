import base64
import hashlib
import json
import os
import re
import time

from datetime import datetime, timezone, timedelta
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.parse import urlsplit, urlunsplit, quote

from checker import check_link


# ==================================================
# FLOGGER VPN PARSER 4.0
# ==================================================

ROOT = Path(__file__).resolve().parent

SOURCES_FILE = ROOT / "sources.txt"
DATABASE_FILE = ROOT / "servers.json"
SUBSCRIPTION_FILE = ROOT / "subscription.txt"
RESULTS_DIR = ROOT / "results"
STATS_FILE = ROOT / "stats.json"

MAX_SERVERS = 50
MAX_AGE_DAYS = 7

CHECK_INTERVAL_HOURS = 12
MAX_FAILURES = 2
KEEP_LAST_SUCCESS_HOURS = 48

VERSION = "4.0"

ALLOWED = (
    "vless://",
    "vmess://",
    "trojan://",
    "ss://",
    "hysteria2://",
    "hy2://",
)

PROTOCOLS = (
    "vless",
    "vmess",
    "trojan",
    "shadowsocks",
    "hysteria2",
)

HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; FloggerVPN/4.0)"
}


# ==================================================
# TIME
# ==================================================

def now():
    return datetime.now(timezone.utc)


def iso(value=None):
    return (value or now()).isoformat()


def parse_date(value):
    if not value:
        return datetime.min.replace(tzinfo=timezone.utc)

    try:
        result = datetime.fromisoformat(value)

        if result.tzinfo is None:
            result = result.replace(tzinfo=timezone.utc)

        return result

    except (TypeError, ValueError):
        return datetime.min.replace(tzinfo=timezone.utc)


def is_recent(value, hours):
    if not value:
        return False

    return now() - parse_date(value) <= timedelta(hours=hours)


# ==================================================
# FILES
# ==================================================

def read_text(path):
    if not path.exists():
        return ""

    return path.read_text(
        encoding="utf-8",
        errors="ignore"
    )


def atomic_write(path, content):
    temporary = path.with_suffix(path.suffix + ".tmp")

    temporary.write_text(
        content,
        encoding="utf-8"
    )

    os.replace(temporary, path)


def save_json(path, data):
    atomic_write(
        path,
        json.dumps(
            data,
            ensure_ascii=False,
            indent=2
        )
    )


# ==================================================
# SOURCE FETCHING
# ==================================================

def fetch_url(url):
    request = Request(
        url,
        headers=HEADERS
    )

    with urlopen(request, timeout=25) as response:
        return response.read().decode(
            "utf-8",
            errors="ignore"
        )


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

            print(
                f"[SOURCE ERROR] {source}: {error}"
            )

            return ""

    return source


# ==================================================
# BASE64
# ==================================================

def decode_base64(value):
    value = value.strip()

    value += "=" * (-len(value) % 4)

    try:

        decoded = base64.b64decode(
            value,
            altchars=b"-_",
            validate=True
        )

        return decoded.decode(
            "utf-8",
            errors="ignore"
        )

    except Exception:
        return ""


# ==================================================
# LINK EXTRACTION
# ==================================================

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

            link = match.rstrip(".,;!)")

            if is_allowed(link):
                found.add(link)

    add_matches(content)

    # Base64 subscription blocks

    candidates = re.findall(
        r'(?<![A-Za-z0-9+/=_-])[A-Za-z0-9_+/=-]{80,}',
        content
    )

    for candidate in candidates:

        decoded = decode_base64(candidate)

        if decoded:
            add_matches(decoded)

    return found


# ==================================================
# PROTOCOL
# ==================================================

def protocol_of(link):

    scheme = link.split("://", 1)[0].lower()

    if scheme == "hy2":
        return "hysteria2"

    if scheme == "ss":
        return "shadowsocks"

    return scheme


# ==================================================
# CONFIGURATION ID
# ==================================================

def config_id(link):

    # Fragment is only a display name.
    # Different names must not create duplicate servers.

    canonical = link.split("#", 1)[0].strip()

    return hashlib.sha256(
        canonical.encode("utf-8")
    ).hexdigest()


# ==================================================
# DATABASE
# ==================================================

def load_database():

    if not DATABASE_FILE.exists():

        return {
            "version": 4,
            "updated": None,
            "servers": []
        }

    try:

        data = json.loads(
            DATABASE_FILE.read_text(
                encoding="utf-8"
            )
        )

        if not isinstance(data, dict):
            raise ValueError("Database must be an object")

        if not isinstance(data.get("servers"), list):
            data["servers"] = []

        data.setdefault("version", 4)
        data.setdefault("updated", None)

        return data

    except Exception as error:

        raise RuntimeError(
            f"Cannot read servers.json: {error}"
        )


def save_database(database):

    database["version"] = 4
    database["updated"] = iso()

    save_json(
        DATABASE_FILE,
        database
    )


# ==================================================
# SERVER NAME
# ==================================================

def update_server_name(link, result):

    country_code = result.get("country_code")
    new_name = result.get("server_name")

    # Do not replace the original name
    # if country detection failed.

    if not country_code or not new_name:
        return link

    parsed = urlsplit(link)

    return urlunsplit((
        parsed.scheme,
        parsed.netloc,
        parsed.path,
        parsed.query,
        quote(new_name, safe="")
    ))


# ==================================================
# CHECK SCHEDULE
# ==================================================

def should_check(item):

    last_checked = item.get("last_checked")

    if not last_checked:
        return True

    return (
        now() - parse_date(last_checked)
        >= timedelta(hours=CHECK_INTERVAL_HOURS)
    )


# ==================================================
# SOURCE COLLECTION
# ==================================================

def collect_sources(sources):

    discovered = {}
    source_errors = 0

    for source in sources:

        print(f"\n[FETCH] {source}")

        content = get_source_content(source)

        if not content:

            source_errors += 1

            continue

        links = extract_links(content)

        print(
            f"[FOUND] {len(links)} configurations"
        )

        for link in links:

            identifier = config_id(link)

            discovered[identifier] = link

    return discovered, source_errors


# ==================================================
# ADD NEW SERVERS
# ==================================================

def update_discovered(servers, discovered):

    existing = {
        item["id"]: item
        for item in servers
        if item.get("id")
    }

    new_count = 0

    for identifier, link in discovered.items():

        if identifier in existing:

            item = existing[identifier]

            item["last_seen"] = iso()

            # Refresh display name without changing ID.

            if link != item.get("link"):
                item["link"] = link

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
                "status": "untested",
                "ip": None,
                "country": None,
                "country_code": None
            }

            servers.append(item)

            existing[identifier] = item

            new_count += 1

    return new_count


# ==================================================
# CHECK RESULT
# ==================================================

def apply_check_result(item, result):

    item["last_checked"] = iso()

    item["cloudflare"] = bool(
        result.get("cloudflare")
    )

    item["google"] = bool(
        result.get("google")
    )

    if result.get("ip"):
        item["ip"] = result["ip"]

    if result.get("country"):
        item["country"] = result["country"]

    if result.get("country_code"):
        item["country_code"] = result["country_code"]

    if result.get("server_name"):

        item["server_name"] = result["server_name"]

        item["link"] = update_server_name(
            item["link"],
            result
        )

    # Successful configuration

    if result.get("working"):

        item["status"] = "working"
        item["last_success"] = iso()
        item["failures"] = 0

        item.pop("check_error", None)

        return "working"

    # Technical error: do not count as server failure.

    if result.get("error"):

        item["status"] = (
            "check_error"
            if not item.get("last_success")
            else "working"
        )

        item["check_error"] = str(
            result["error"]
        )[:250]

        return "error"

    # Both endpoint checks failed.

    item["failures"] = (
        int(item.get("failures", 0)) + 1
    )

    if item["failures"] >= MAX_FAILURES:

        item["status"] = "dead"

        return "dead"

    item["status"] = "suspect"

    return "suspect"


# ==================================================
# SERVER CHECKING
# ==================================================

def check_servers(servers):

    checked = 0
    working = []
    check_errors = 0
    removed_dead = 0
    skipped = 0

    for index, item in enumerate(
        servers,
        start=1
    ):

        link = item.get("link", "")

        if not link:
            continue

        if not should_check(item):

            skipped += 1

            print(
                f"[SKIP] {item.get('protocol')} "
                f"- checked recently"
            )

            if (
                item.get("status") == "working"
                and item.get("last_success")
            ) or (
                item.get("status") == "suspect"
                and is_recent(
                    item.get("last_success"),
                    KEEP_LAST_SUCCESS_HOURS
                )
            ):

                working.append(item)

            continue

        checked += 1

        print(
            f"\n[CHECK {index}/{len(servers)}] "
            f"{item.get('protocol', 'unknown')}"
        )

        try:

            result = check_link(link)

            if not isinstance(result, dict):
                raise ValueError(
                    "Invalid checker response"
                )

        except Exception as error:

            result = {
                "working": False,
                "cloudflare": False,
                "google": False,
                "error": str(error)[:250]
            }

        status = apply_check_result(
            item,
            result
        )

        if status == "working":

            working.append(item)

            print(
                "[WORKING] "
                f"Cloudflare={item.get('cloudflare')} "
                f"Google={item.get('google')}"
            )

        elif status == "error":

            check_errors += 1

            print(
                f"[CHECK ERROR] "
                f"{item.get('check_error')}"
            )

            # Keep recently verified servers
            # during temporary checker failures.

            if is_recent(
                item.get("last_success"),
                KEEP_LAST_SUCCESS_HOURS
            ):

                working.append(item)

        elif status == "suspect":

            print(
                f"[SUSPECT] Failures: "
                f"{item['failures']}/{MAX_FAILURES}"
            )

            if is_recent(
                item.get("last_success"),
                KEEP_LAST_SUCCESS_HOURS
            ):

                working.append(item)

        elif status == "dead":

            removed_dead += 1

            print("[DEAD] Removed after repeated failures")

    return (
        working,
        checked,
        skipped,
        check_errors,
        removed_dead
    )


# ==================================================
# DATABASE CLEANUP
# ==================================================

def cleanup_servers(servers):

    cutoff = now() - timedelta(
        days=MAX_AGE_DAYS
    )

    before = len(servers)

    cleaned = []

    for item in servers:

        if item.get("status") == "dead":
            continue

        last_seen = parse_date(
            item.get("last_seen")
            or item.get("first_seen")
        )

        if last_seen < cutoff:
            continue

        cleaned.append(item)

    expired = before - len(cleaned)

    return cleaned, expired


# ==================================================
# SUBSCRIPTION EXPORT
# ==================================================

def write_results(exportable):

    RESULTS_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    groups = {
        protocol: []
        for protocol in PROTOCOLS
    }

    for item in exportable:

        protocol = item.get("protocol")
        link = item.get("link")

        if protocol in groups and link:

            groups[protocol].append(link)

    for protocol, links in groups.items():

        output = RESULTS_DIR / f"{protocol}.txt"

        atomic_write(
            output,
            "\n".join(links)
        )

    subscription = "\n".join(
        item["link"]
        for item in exportable
    )

    atomic_write(
        SUBSCRIPTION_FILE,
        subscription
    )


# ==================================================
# STATISTICS
# ==================================================

def write_stats(stats):

    save_json(
        STATS_FILE,
        stats
    )


# ==================================================
# MAIN
# ==================================================

def main():

    started = time.time()

    print("=" * 55)
    print(f"       FLOGGER VPN PARSER {VERSION}")
    print("=" * 55)

    RESULTS_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    if not SOURCES_FILE.exists():

        raise FileNotFoundError(
            "sources.txt not found"
        )

    sources = [
        line.strip()
        for line in read_text(
            SOURCES_FILE
        ).splitlines()
        if line.strip()
        and not line.strip().startswith("#")
    ]

    print(f"[INFO] Sources: {len(sources)}")

    database = load_database()

    servers = database["servers"]

    # Collect links

    discovered, source_errors = collect_sources(
        sources
    )

    print(
        f"\n[INFO] Unique configurations: "
        f"{len(discovered)}"
    )

    # Update database

    new_count = update_discovered(
        servers,
        discovered
    )

    print(f"[INFO] New servers: {new_count}")

    # Check servers

    print("\n" + "=" * 55)
    print("STARTING SERVER CHECKS")
    print("=" * 55)

    (
        working_servers,
        checked,
        skipped,
        check_errors,
        removed_dead
    ) = check_servers(servers)

    # Remove dead and expired servers

    servers, expired = cleanup_servers(
        servers
    )

    # Remove duplicate export entries

    unique_working = {}

    for item in working_servers:

        if item.get("status") in (
            "working",
            "suspect"
        ):

            unique_working[item["id"]] = item

    working_servers = list(
        unique_working.values()
    )

    # Sort by last successful check

    working_servers.sort(
        key=lambda item: parse_date(
            item.get("last_success")
        ),
        reverse=True
    )

    # Maximum subscription size

    exportable = working_servers[:MAX_SERVERS]

    # Save everything

    database["servers"] = servers

    save_database(database)

    write_results(exportable)

    duration = round(
        time.time() - started,
        2
    )

    stats = {
        "version": VERSION,
        "updated": iso(),
        "sources": len(sources),
        "source_errors": source_errors,
        "found": len(discovered),
        "new": new_count,
        "history": len(servers),
        "expired": expired,
        "checked": checked,
        "skipped": skipped,
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
        "ip_detection": True,
        "country_detection": True,
        "renaming": True,
        "check_interval_hours": CHECK_INTERVAL_HOURS,
        "duration_seconds": duration
    }

    write_stats(stats)

    # Final output

    print("\n" + "=" * 55)
    print("       FLOGGER VPN RESULTS")
    print("=" * 55)

    print(f"Sources:          {len(sources)}")
    print(f"Source errors:    {source_errors}")
    print(f"Found:            {len(discovered)}")
    print(f"New:              {new_count}")
    print(f"Checked:          {checked}")
    print(f"Skipped:          {skipped}")
    print(f"Working:          {len(working_servers)}")
    print(f"Exported:         {len(exportable)}/{MAX_SERVERS}")
    print(f"Removed dead:     {removed_dead}")
    print(f"Expired:          {expired}")
    print(f"Check errors:     {check_errors}")
    print(f"Duration:         {duration} sec")

    print("=" * 55)

    print("\n[OK] Database saved")
    print("[OK] Subscription updated")
    print("[OK] Statistics updated")


if __name__ == "__main__":

    main()
        
