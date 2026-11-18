import base64
import hashlib
import html
import json
import os
import re
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from urllib.parse import urlsplit, parse_qs, unquote

import requests
import urllib3
from checker import check_link

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

ROOT = Path(__file__).resolve().parent

SOURCES_FILE = ROOT / "sources.txt"
DATABASE_FILE = ROOT / "servers.json"
SUBSCRIPTION_FILE = ROOT / "subscription.txt"
RESULTS_DIR = ROOT / "results"
STATS_FILE = ROOT / "stats.json"

MAX_SERVERS = 70
VERSION = "7.9"

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
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.9",
}

LINK_PATTERN = re.compile(r'(?i)(?:vless|vmess|trojan|ss|hysteria2|hy2)://[^\s<>"\'\]\[{}\\]+')
ENCODED_LINK_PATTERN = re.compile(r'(?i)(?:vless|vmess|trojan|ss|hysteria2|hy2)%3A%2F%2F[^\s<>"\'\]\[{}\\&]+')
BASE64_PATTERN = re.compile(r'(?<![A-Za-z0-9+/=_-])[A-Za-z0-9_+/=-]{20,}')


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


def atomic_write(path, content):
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(content, encoding="utf-8")
    os.replace(temporary, path)


def save_json(path, data):
    atomic_write(path, json.dumps(data, ensure_ascii=False, indent=2))


def decode_base64(value):
    value = value.strip()
    if not value:
        return ""
    value_padded = value + "=" * (-len(value) % 4)
    for altchars in (b"-_", b"+/"):
        try:
            decoded = base64.b64decode(value_padded, altchars=altchars, validate=False)
            res = decoded.decode("utf-8", errors="ignore")
            if "://" in res:
                return res
        except Exception:
            continue
    return ""


def extract_real_target_url(source):
    parsed = urlsplit(source)
    query_params = parse_qs(parsed.query)

    for key in ("url", "sub", "link", "target", "file", "data"):
        if key in query_params:
            inner_url = unquote(query_params[key][0])
            if inner_url.startswith(("http://", "https://")):
                return inner_url
    return source


def download(url):
    session = requests.Session()
    session.trust_env = False
    for verify in (True, False):
        try:
            r = session.get(url, headers=HEADERS, timeout=25,
                            allow_redirects=True, verify=verify)
            if r.status_code != 200:
                print(f"[SKIP] HTTP {r.status_code} for {url}")
                return ""
            return r.content.decode("utf-8", errors="ignore").strip()
        except requests.exceptions.SSLError:
            continue  # повтор без проверки сертификата
        except Exception as e:
            print(f"[SKIP] Failed to fetch {url}: {e}")
            return ""
    return ""


def fetch_url(raw_url):
    raw_url = raw_url.strip().replace(" ", "%20")
    inner = extract_real_target_url(raw_url).strip().replace(" ", "%20")

    targets = [raw_url]
    if inner != raw_url:
        targets.append(inner)

    candidates = []
    for target in targets:
        candidates.append(target)
        if target.startswith("http://"):
            candidates.append("https://" + target[len("http://"):])
        elif target.startswith("https://"):
            candidates.append("http://" + target[len("https://"):])

    last_text = ""
    for url in candidates:
        text = download(url)
        if not text:
            continue
        if extract_links(text):
            return text
        decoded = decode_base64(text)
        if decoded:
            return decoded
        last_text = last_text or text
    return last_text


def get_source_content(source):
    source = source.strip()
    if not source or source.startswith("#"):
        return ""
    if source.startswith(("http://", "https://")):
        try:
            target_url = source
            if "t.me/" in source and "/s/" not in source:
                channel = source.rstrip("/").split("/")[-1]
                target_url = f"https://t.me/s/{channel}"
            return fetch_url(target_url)
        except Exception as error:
            print(f"[SOURCE ERROR] {source}: {error}")
            return ""
    return source


def is_allowed(link):
    return link.lower().startswith(ALLOWED)


def extract_links(content):
    found = set()

    def add_matches(text):
        text = html.unescape(text).replace("\\/", "/")
        for match in LINK_PATTERN.findall(text):
            link = match.rstrip(".,;!)")
            if is_allowed(link):
                found.add(link)
        for match in ENCODED_LINK_PATTERN.findall(text):
            link = unquote(match).rstrip(".,;!)")
            if is_allowed(link):
                found.add(link)

    add_matches(content)
    for candidate in BASE64_PATTERN.findall(content):
        decoded = decode_base64(candidate)
        if decoded:
            add_matches(decoded)
    return found


def get_telegram_new_links(content, stored_last_id):
    new_links = set()
    max_id = stored_last_id
    parts = content.split('class="tgme_widget_message ')

    if len(parts) > 1:
        for part in parts[1:]:
            post_id_match = re.search(r'data-post="[^/]+/(\d+)"', part)
            if not post_id_match:
                post_id_match = re.search(r'href="https://t.me/[^/]+/(\d+)"', part)
            if post_id_match:
                try:
                    post_id = int(post_id_match.group(1))
                except ValueError:
                    continue
                max_id = max(max_id, post_id)
                if post_id > stored_last_id:
                    new_links.update(extract_links(part))
    else:
        # страница не похожа на ленту Telegram — ищем по всему тексту
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


def empty_database():
    return {"version": VERSION, "updated": None, "servers": [], "channels": {}}


def load_database():
    if not DATABASE_FILE.exists():
        return empty_database()
    try:
        data = json.loads(DATABASE_FILE.read_text(encoding="utf-8"))
        data.setdefault("servers", [])
        data.setdefault("channels", {})
        data["version"] = VERSION
        return data
    except Exception:
        return empty_database()


def save_database(database):
    database["version"] = VERSION
    database["updated"] = iso()
    save_json(DATABASE_FILE, database)


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
            print(f"[TG] Channel: {channel_slug} | Found links: {len(links)}")
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
    item["google"] = bool(result.get("google"))

    if result.get("ip"):
        item["ip"] = result["ip"]
    if result.get("country"):
        item["country"] = result["country"]
    if result.get("country_code"):
        item["country_code"] = result["country_code"]
    if result.get("server_name"):
        item["server_name"] = result["server_name"]
        if result.get("link"):
            item["link"] = result["link"]

    if result.get("working"):
        item["status"] = "working"
        item["last_success"] = iso()
        item["failures"] = 0
        return "working"

    item["status"] = "dead"
    item["failures"] = item.get("failures", 0) + 1
    return "dead"


def check_servers(servers):
    checked = 0
    working = []
    removed_dead = 0

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
            print(f"[WORKING] Ping={result.get('ping')}ms | {item.get('server_name')}")
        else:
            print("[DEAD] Removing.")
            removed_dead += 1

    return working, checked, removed_dead


def cleanup_servers(servers):
    cleaned = []
    expired = 0
    cutoff_12h = now() - timedelta(hours=12)

    for item in servers:
        status = item.get("status")
        last_success = parse_date(item.get("last_success"))

        if status != "working" or last_success < cutoff_12h:
            expired += 1
            continue
        cleaned.append(item)

    print(f"[CLEANUP] Removed dead/old: {expired}. Kept working: {len(cleaned)}")
    return cleaned, expired


def write_results(exportable):
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    groups = {protocol: [] for protocol in PROTOCOLS}
    for item in exportable:
        protocol = item.get("protocol")
        link = item.get("link")
        if protocol in groups and link:
            groups[protocol].append(link)

    for protocol, links in groups.items():
        atomic_write(RESULTS_DIR / f"{protocol}.txt", "\n".join(links))

    atomic_write(SUBSCRIPTION_FILE, "\n".join(item["link"] for item in exportable if item.get("link")))


def main():
    started = time.time()
    print("=" * 55)
    print(f"       FLOGGER VPN PARSER {VERSION}")
    print("=" * 55)

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    if not SOURCES_FILE.exists():
        raise FileNotFoundError("sources.txt not found")

    sources = [
        line.strip()
        for line in SOURCES_FILE.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]

    database = load_database()
    servers = database["servers"]

    servers, expired = cleanup_servers(servers)
    discovered, source_errors = collect_sources(sources, database)
    new_count = update_discovered(servers, discovered)

    print(f"\n[INFO] Checking {len(servers)} current configurations...")
    working_servers, checked, removed_dead = check_servers(servers)

    unique_working = {item["id"]: item for item in working_servers}
    working_servers = list(unique_working.values())
    working_servers.sort(key=lambda x: parse_date(x.get("last_success")), reverse=True)

    exportable = working_servers[:MAX_SERVERS]
    database["servers"] = working_servers
    save_database(database)
    write_results(exportable)

    stats = {
        "version": VERSION,
        "updated": iso(),
        "sources": len(sources),
        "source_errors": source_errors,
        "found": len(discovered),
        "new": new_count,
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
