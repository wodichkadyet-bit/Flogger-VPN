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
# FLOGGER VPN PARSER 4.3 (Full Check Every Run)
# ==================================================

ROOT = Path(__file__).resolve().parent

SOURCES_FILE = ROOT / "sources.txt"
DATABASE_FILE = ROOT / "servers.json"
SUBSCRIPTION_FILE = ROOT / "subscription.txt"
RESULTS_DIR = ROOT / "results"
STATS_FILE = ROOT / "stats.json"

MAX_SERVERS = 50
MAX_AGE_DAYS = 7
MAX_FAILURES = 2
KEEP_LAST_SUCCESS_HOURS = 48

VERSION = "4.3"

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
    "User-Agent": "Mozilla/5.0 (compatible; FloggerVPN/4.3)"
}


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

def atomic_write(path, content):
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(content, encoding="utf-8")
    os.replace(temporary, path)

def save_json(path, data):
    atomic_write(path, json.dumps(data, ensure_ascii=False, indent=2))

def fetch_url(url):
    request = Request(url, headers=HEADERS)
    with urlopen(request, timeout=25) as response:
        return response.read().decode("utf-8", errors="ignore")

def get_source_content(source):
    source = source.strip()
    if not source or source.startswith("#"):
        return ""
    if source.startswith(("http://", "https://")):
        try:
            if "t.me/" in source and "/s/" not in source:
                channel = source.rstrip("/").split("/")[-1]
                return fetch_url(f"https://t.me/s/{channel}")
            return fetch_url(source)
        except Exception as error:
            print(f"[SOURCE ERROR] {source}: {error}")
            return ""
    return source

def decode_base64(value):
    value = value.strip() + "=" * (-len(value) % 4)
    try:
        decoded = base64.b64decode(value, altchars=b"-_", validate=True)
        return decoded.decode("utf-8", errors="ignore")
    except Exception:
        return ""

def is_allowed(link):
    return link.lower().startswith(ALLOWED)

def extract_links(content):
    found = set()
    pattern = r'(?i)(?:vless|vmess|trojan|ss|hysteria2|hy2)://[^\s<>"\'\]\[{}]+'
    
    def add_matches(text):
        for match in re.findall(pattern, text):
            link = match.rstrip(".,;!)")
            if is_allowed(link):
                found.add(link)

    add_matches(content)
    for candidate in re.findall(r'(?<![A-Za-z0-9+/=_-])[A-Za-z0-9_+/=-]{80,}', content):
        decoded = decode_base64(candidate)
        if decoded:
            add_matches(decoded)
    return found

def get_telegram_new_links(content, stored_last_id):
    new_links = set()
    max_id = stored_last_id
    parts = content.split('class="tgme_widget_message ')

    for part in parts[1:]:
        post_id_match = re.search(r'data-post="[^/]+/(\d+)"', part)
        if not post_id_match:
            post_id_match = re.search(r'href="https://t.me/[^/]+/(\d+)"', part)
        if post_id_match:
            try:
                post_id = int(post_id_match.group(1))
                if post_id > max_id:
                    max_id = post_id
                if post_id > stored_last_id:
                    new_links.update(extract_links(part))
            except ValueError:
                pass
        else:
            if stored_last_id == 0:
                new_links.update(extract_links(part))

    if not new_links and stored_last_id == 0:
        new_links = extract_links(content)

    return new_links, max_id

def protocol_of(link):
    scheme = link.split("://", 1)[0].lower()
    if scheme == "hy2":
        return "hysteria2"
    if scheme == "ss":
        return "shadowsocks"
    return scheme

def config_id(link):
    return hashlib.sha256(link.split("#", 1)[0].strip().encode("utf-8")).hexdigest()

def load_database():
    if not DATABASE_FILE.exists():
        return {"version": 4.3, "updated": None, "servers": [], "channels": {}}
    try:
        data = json.loads(DATABASE_FILE.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("Database must be an object")
        data.setdefault("servers", [])
        data.setdefault("channels", {})
        data["version"] = 4.3
        return data
    except Exception as error:
        raise RuntimeError(f"Cannot read servers.json: {error}")

def save_database(database):
    database["version"] = 4.3
    database["updated"] = iso()
    save_json(DATABASE_FILE, database)

def update_server_name(link, result):
    country_code = result.get("country_code")
    new_name = result.get("server_name")
    if not country_code or not new_name:
        return link
    parsed = urlsplit(link)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, parsed.query, quote(new_name, safe="")))

def collect_sources(sources, database):
    discovered = {}
    source_errors = 0
    channels_state = database.setdefault("channels", {})

    for source in sources:
        print(f"\n[FETCH] {source}")
        content = get_source_content(source)
        if not content:
            source_errors += 1
            continue

        if "t.me/" in source:
            channel_slug = source.rstrip("/").split("/")[-1]
            stored_state = channels_state.get(channel_slug, {})
            stored_last_id = stored_state.get("last_message_id", 0)

            links, max_id = get_telegram_new_links(content, stored_last_id)
            channels_state[channel_slug] = {
                "last_message_id": max(stored_last_id, max_id),
                "last_checked": iso()
            }
            print(f"[TG] Channel: {channel_slug} | New links: {len(links)}")
        else:
            links = extract_links(content)
            print(f"[FOUND] {len(links)} configurations")

        for link in links:
            discovered[config_id(link)] = link

    return discovered, source_errors

def update_discovered(servers, discovered):
    existing = {item["id"]: item for item in servers if item.get("id")}
    new_count = 0

    for identifier, link in discovered.items():
        if identifier in existing:
            item = existing[identifier]
            item["last_seen"] = iso()
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

def apply_check_result(item, result):
    item["last_checked"] = iso()
    item["cloudflare"] = bool(result.get("cloudflare"))
    item["google"] = bool(result.get("google"))

    if result.get("ip"):
        item["ip"] = result["ip"]
    if result.get("country"):
        item["country"] = result["country"]
    if result.get("country_code"):
        item["country_code"] = result["country_code"]
    if result.get("server_name"):
        item["server_name"] = result["server_name"]
        item["link"] = update_server_name(item["link"], result)

    if result.get("working"):
        item["status"] = "working"
        item["last_success"] = iso()
        item["failures"] = 0
        item.pop("check_error", None)
        return "working"

    if result.get("error"):
        item["status"] = "check_error" if not item.get("last_success") else "working"
        item["check_error"] = str(result["error"])[:250]
        return "error"

    item["failures"] = int(item.get("failures", 0)) + 1
    if item["failures"] >= MAX_FAILURES:
        item["status"] = "suspect_dead"
        return "suspect_dead"

    item["status"] = "suspect"
    return "suspect"

def check_servers(servers):
    checked = 0
    working = []
    check_errors = 0
    removed_dead = 0
    candidates_for_deletion = []

    for index, item in enumerate(servers, start=1):
        link = item.get("link", "")
        if not link:
            continue

        checked += 1
        print(f"\n[CHECK {index}/{len(servers)}] {item.get('protocol', 'unknown')}")

        try:
            result = check_link(link)
        except Exception as error:
            result = {"working": False, "error": str(error)[:250]}

        status = apply_check_result(item, result)

        if status == "working":
            working.append(item)
            print(f"[WORKING] CF={item.get('cloudflare')} Google={item.get('google')}")
        elif status == "error":
            check_errors += 1
            if is_recent(item.get("last_success"), KEEP_LAST_SUCCESS_HOURS):
                working.append(item)
        elif status == "suspect":
            if is_recent(item.get("last_success"), KEEP_LAST_SUCCESS_HOURS):
                working.append(item)
        elif status == "suspect_dead":
            candidates_for_deletion.append(item)

    # Подтверждающая проверка для удаления мертвых
    if candidates_for_deletion:
        print("\n" + "=" * 45)
        print("RUNNING CONFIRMATION CHECK FOR DEAD SERVERS")
        print("=" * 45)
        for item in candidates_for_deletion:
            try:
                re_result = check_link(item.get("link", ""))
            except Exception:
                re_result = {"working": False}

            if re_result.get("working"):
                print("[RE-CHECK] Recovered! Keeping server.")
                item["status"] = "working"
                item["last_success"] = iso()
                item["failures"] = 0
                working.append(item)
            else:
                print("[RE-CHECK] Confirmed dead. Removing.")
                item["status"] = "dead"
                removed_dead += 1

    return working, checked, 0, check_errors, removed_dead

def cleanup_servers(servers):
    cutoff = now() - timedelta(days=MAX_AGE_DAYS)
    before = len(servers)
    cleaned = []
    for item in servers:
        if item.get("status") == "dead":
            continue
        last_seen = parse_date(item.get("last_seen") or item.get("first_seen"))
        if last_seen < cutoff:
            continue
        cleaned.append(item)
    return cleaned, before - len(cleaned)

def write_results(exportable):
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    groups = {protocol: [] for protocol in PROTOCOLS}
    for item in exportable:
        if item.get("protocol") in groups and item.get("link"):
            groups[item.get("protocol")].append(item.get("link"))

    for protocol, links in groups.items():
        atomic_write(RESULTS_DIR / f"{protocol}.txt", "\n".join(links))

    atomic_write(SUBSCRIPTION_FILE, "\n".join(item["link"] for item in exportable))

def main():
    started = time.time()
    print("=" * 55)
    print(f"       FLOGGER VPN PARSER {VERSION}")
    print("=" * 55)

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    if not SOURCES_FILE.exists():
        raise FileNotFoundError("sources.txt not found")

    sources = [l.strip() for l in SOURCES_FILE.read_text(encoding="utf-8").splitlines() if l.strip() and not l.startswith("#")]
    database = load_database()
    servers = database["servers"]

    discovered, source_errors = collect_sources(sources, database)
    new_count = update_discovered(servers, discovered)

    print("\n" + "=" * 55)
    print("STARTING FULL SERVER CHECKS (ALL SERVERS)")
    print("=" * 55)

    working_servers, checked, _, check_errors, removed_dead = check_servers(servers)
    servers, expired = cleanup_servers(servers)

    unique_working = {item["id"]: item for item in working_servers if item.get("status") in ("working", "suspect", "suspect_dead")}
    working_servers = list(unique_working.values())
    working_servers.sort(key=lambda x: parse_date(x.get("last_success")), reverse=True)

    exportable = working_servers[:MAX_SERVERS]
    database["servers"] = servers
    save_database(database)
    write_results(exportable)

    stats = {
        "version": VERSION,
        "updated": iso(),
        "sources": len(sources),
        "found": len(discovered),
        "new": new_count,
        "history": len(servers),
        "expired": expired,
        "checked": checked,
        "working": len(working_servers),
        "subscription": len(exportable),
        "removed_dead": removed_dead,
        "duration_seconds": round(time.time() - started, 2)
    }
    save_json(STATS_FILE, stats)
    print("\n[OK] Parser finished successfully.")

if __name__ == "__main__":
    main()
                                     
