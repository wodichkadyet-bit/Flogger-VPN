import base64
import hashlib
import html
import json
import os
import re
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from urllib.parse import urlsplit, parse_qs, unquote, urljoin

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

MAX_SERVERS = 50
SERVER_TTL_HOURS = 24  # сервер, которого уже сутки нет ни в одном источнике, удаляется
# Оформление подписки в клиенте (читается из первых строк subscription.txt)
PROFILE_TITLE = "Flogger VPN"
PROFILE_ANNOUNCE = "✨ Наш ТГ канал: https://t.me/Flogger_VPN | 🆓 Бесплатная подписка ЧС | ✅ Без Ограничений!"
PROFILE_UPDATE_INTERVAL = 1  # как часто клиент сам обновляет подписку, в часах

SERVER_MAX_AGE_HOURS = 48  # сервер старше этого возраста считается старым и идёт в подписку в последнюю очередь
MIN_SERVERS = 10  # если свежих меньше, подписку добирают старыми, чтобы она не опустела
HISTORY_DAYS = 30  # сколько дней помнить, когда сервер впервые появился
MAX_PING = 1500  # мс; более медленные серверы не попадают в подписку
VERSION = "8.6"

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
        for attempt in range(2):
            try:
                r = session.get(url, headers=HEADERS, timeout=25,
                                allow_redirects=True, verify=verify)
            except requests.exceptions.SSLError:
                break  # повтор без проверки сертификата
            except Exception as e:
                print(f"[SKIP] Failed to fetch {url}: {e}")
                return ""
            if r.status_code in (429, 500, 502, 503, 504) and attempt == 0:
                time.sleep(2)  # временная ошибка сервера: пробуем ещё раз
                continue
            if r.status_code != 200:
                print(f"[SKIP] HTTP {r.status_code} for {url}")
                return ""
            return r.content.decode("utf-8", errors="ignore").strip()
    return ""


def alternative_urls(url):
    """Запасные адреса для того же файла. Codeberg часто закрывает обычный raw
    (403), но отдаёт тот же файл через свой API."""
    parsed = urlsplit(url)
    host = (parsed.hostname or "").lower()
    match = re.match(r"^/([^/]+)/([^/]+)/raw/(?:branch|tag|commit)/([^/]+)/(.+)$", parsed.path)
    if host in ("codeberg.org", "www.codeberg.org") and match:
        owner, repo, ref, path = match.groups()
        return [f"https://codeberg.org/api/v1/repos/{owner}/{repo}/raw/{path}?ref={ref}"]
    return []


def fetch_url(raw_url):
    raw_url = raw_url.strip().replace(" ", "%20")
    inner = extract_real_target_url(raw_url).strip().replace(" ", "%20")

    # сначала исходная ссылка (посредник), потом вложенная
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

    for target in targets:
        candidates.extend(alternative_urls(target))

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


TELEGRAM_HOSTS = ("t.me", "telegram.me", "telegram.dog")


def telegram_channel(source):
    """Имя канала, если source — ссылка на Telegram-канал, иначе None"""
    parsed = urlsplit(source)
    if (parsed.hostname or "").lower() not in TELEGRAM_HOSTS:
        return None
    parts = [p for p in parsed.path.split("/") if p]
    if not parts:
        return None
    if parts[0] == "s" and len(parts) > 1:
        return parts[1]
    return parts[0]


def report_telegram_page(content):
    """Диагностика: что именно получил парсер от Telegram"""
    posts = content.count('data-post="')
    raw = len(re.findall(r"(?i)(?:vless|vmess|trojan|ss|hysteria2|hy2)://", content))
    print(f"[TG] Page: {len(content)} chars | posts: {posts} | raw links in text: {raw}")
    if posts == 0:
        text = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", content)).strip()
        print(f"[TG] WARNING: no posts on page (preview disabled or blocked). Text: {text[:200]}")


TELEGRAM_PAGES = 2  # сколько страниц (по ~20 постов) читать назад: 2 страницы = 40 постов


def fetch_telegram_channel(channel):
    """Читает последние посты канала через веб-просмотр t.me/s/..."""
    pages = []
    before = None
    for _ in range(TELEGRAM_PAGES):
        text = ""
        for host in ("t.me", "telegram.me"):
            url = f"https://{host}/s/{channel}"
            if before:
                url += f"?before={before}"
            text = fetch_url(url)
            if "tgme_widget_message" in text:
                break
        if "tgme_widget_message" not in text:
            if not pages:
                return text  # пусть диагностика покажет, что пришло
            break
        pages.append(text)
        ids = [int(i) for i in re.findall(r'data-post="[^/"]+/(\d+)"', text)]
        if not ids or min(ids) <= 1:
            break
        before = min(ids)
    return "\n".join(pages)


def get_source_content(source):
    source = source.strip()
    if not source or source.startswith("#"):
        return ""
    if source.startswith(("http://", "https://")):
        try:
            channel = telegram_channel(source)
            if channel:
                return fetch_telegram_channel(channel)
            return fetch_url(source)
        except Exception as error:
            print(f"[SOURCE ERROR] {source}: {error}")
            return ""
    return source


FOLLOW_LIMIT = 10  # сколько ссылок со страницы открывать
FOLLOW_EXTENSIONS = (".txt", ".list", ".conf", ".yaml", ".yml", ".json", ".sub")
FOLLOW_SKIP_HOSTS = (
    "t.me", "telegram.me", "telegram.org", "github.com", "youtube.com", "youtu.be",
    "google.com", "facebook.com", "twitter.com", "x.com", "instagram.com", "vk.com",
    "play.google.com", "apps.apple.com",
)


def find_followable(content, base_url):
    """Ссылки на страницы с подписками/списками внутри HTML"""
    text = html.unescape(content)
    found = []
    for attr, bare in re.findall(r'(?:href|src)=["\']([^"\'#]+)["\']|(https?://[^\s"\'<>]+)', text):
        url = urljoin(base_url, (attr or bare).strip())
        parsed = urlsplit(url)
        host = (parsed.hostname or "").lower()
        path = parsed.path.lower()
        if parsed.scheme not in ("http", "https") or not host:
            continue
        if any(host == s or host.endswith("." + s) for s in FOLLOW_SKIP_HOSTS):
            continue
        if path.endswith(FOLLOW_EXTENSIONS) or "/sub" in path or "subscri" in path or "/raw/" in path:
            if url not in found:
                found.append(url)
    return found[:FOLLOW_LIMIT]


def follow_links(content, base_url):
    """Если на странице нет конфигов, открываем ссылки на подписки внутри неё"""
    links = set()
    for url in find_followable(content, base_url):
        inner = fetch_url(url)
        got = extract_links(inner) if inner else set()
        print(f"[FOLLOW] {url} -> {len(got)} configurations")
        links.update(got)
    return links


def is_allowed(link):
    low = link.lower()
    if not low.startswith(ALLOWED):
        return False
    # заглушки вида "пользователь не найден"
    if "@127.0.0.1" in low or "@localhost" in low or "00000000-0000-0000-0000-000000000000" in low:
        return False
    return True


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

        channel_slug = telegram_channel(source)
        if channel_slug:
            stored_last_id = channels_state.get(channel_slug, {}).get("last_message_id", 0)

            # Каждый раз читаем ВСЕ посты со страниц, а не только новые:
            # так ключи не теряются, если сервер был удалён из базы,
            # а в базе дубликаты всё равно отсеиваются по id.
            links = extract_links(content)
            post_ids = [int(i) for i in re.findall(r'data-post="[^/"]+/(\d+)"', content)]
            channels_state[channel_slug] = {
                "last_message_id": max([stored_last_id] + post_ids),
                "last_checked": iso()
            }
            print(f"[TG] Channel: {channel_slug} | Found links: {len(links)}")
            report_telegram_page(content)
        else:
            links = extract_links(content)
            if not links and source.startswith(("http://", "https://")):
                links = follow_links(content, source)
            print(f"[FOUND] {len(links)} configurations")
            if not links:
                snippet = re.sub(r"\s+", " ", content)[:200]
                print(f"[DEBUG] {len(content)} chars, no links. Starts with: {snippet}")

        for link in links:
            discovered[config_id(link)] = link

    return discovered, source_errors


def update_discovered(servers, discovered, history):
    """history хранит, когда сервер ВПЕРВЫЕ появился. Даже если он выпал из базы и
    вернулся из источника, он остаётся «старым»."""
    existing = {item["id"]: item for item in servers if item.get("id")}
    new_count = 0
    stamp = iso()

    for item in servers:
        if item.get("id"):
            history.setdefault(item["id"], {
                "first": item.get("first_seen") or stamp,
                "last": item.get("last_seen") or stamp,
            })

    for identifier, link in discovered.items():
        record = history.setdefault(identifier, {"first": stamp, "last": stamp})
        record["last"] = stamp

        if identifier in existing:
            item = existing[identifier]
            item["last_seen"] = stamp
            item["first_seen"] = record["first"]
            if link != item.get("link"):
                item["link"] = link
        else:
            item = {
                "id": identifier,
                "protocol": protocol_of(link),
                "link": link,
                "first_seen": record["first"],
                "last_seen": stamp,
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


def prune_history(history):
    cutoff = now() - timedelta(days=HISTORY_DAYS)
    for identifier in [i for i, rec in history.items() if parse_date(rec.get("last")) < cutoff]:
        del history[identifier]


def is_fresh(item):
    cutoff = now() - timedelta(hours=SERVER_MAX_AGE_HOURS)
    return parse_date(item.get("first_seen")) >= cutoff


def apply_check_result(item, result):
    item["last_checked"] = iso()
    item["google"] = bool(result.get("google"))
    item["telegram"] = bool(result.get("telegram"))

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
        item["ping"] = result.get("ping")
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
    cutoff_seen = now() - timedelta(hours=SERVER_TTL_HOURS)

    for item in servers:
        status = item.get("status")
        last_success = parse_date(item.get("last_success"))
        last_seen = parse_date(item.get("last_seen") or item.get("last_success"))

        # удаляем: нерабочие, давно не проверенные и пропавшие из источников
        if status != "working" or last_success < cutoff_12h or last_seen < cutoff_seen:
            expired += 1
            continue
        cleaned.append(item)

    print(f"[CLEANUP] Removed dead/old: {expired}. Kept working: {len(cleaned)}")
    return cleaned, expired


def b64_header(text):
    """Текст с кириллицей и эмодзи передаётся в base64, так его понимают все клиенты"""
    return "base64:" + base64.b64encode(text.encode("utf-8")).decode("ascii")


def subscription_header():
    return "\n".join([
        f"#profile-title: {b64_header(PROFILE_TITLE)}",
        f"#profile-update-interval: {PROFILE_UPDATE_INTERVAL}",
        f"#announce: {b64_header(PROFILE_ANNOUNCE)}",
    ])


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

    # удаляем файлы, оставшиеся от старых версий парсера
    keep = {f"{protocol}.txt" for protocol in PROTOCOLS}
    for stale in RESULTS_DIR.glob("*.txt"):
        if stale.name not in keep:
            stale.unlink()
            print(f"[CLEANUP] Removed stale file: {stale.name}")

    links_text = "\n".join(item["link"] for item in exportable if item.get("link"))
    atomic_write(SUBSCRIPTION_FILE, subscription_header() + "\n" + links_text)


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
    history = database.setdefault("history", {})

    servers, expired = cleanup_servers(servers)
    discovered, source_errors = collect_sources(sources, database)
    new_count = update_discovered(servers, discovered, history)
    prune_history(history)

    print(f"\n[INFO] Checking {len(servers)} current configurations...")
    working_servers, checked, removed_dead = check_servers(servers)

    unique_working = {item["id"]: item for item in working_servers}
    working_servers = [x for x in unique_working.values() if (x.get("ping") or 99999) <= MAX_PING]
    working_servers.sort(key=lambda x: x.get("ping") or 99999)

    # свежие серверы идут в подписку в первую очередь, старые (старше
    # SERVER_MAX_AGE_HOURS) только если свежих слишком мало
    fresh = [x for x in working_servers if is_fresh(x)]
    old = [x for x in working_servers if not is_fresh(x)]
    exportable = fresh[:MAX_SERVERS]
    if len(exportable) < MIN_SERVERS:
        filler = old[:MIN_SERVERS - len(exportable)]
        exportable += filler
        print(f"[OLD] Fresh servers: {len(fresh)}. Added {len(filler)} old to reach minimum {MIN_SERVERS}.")
    print(f"[INFO] Working: {len(working_servers)} | fresh: {len(fresh)} | old skipped: {len(old) - (len(exportable) - len(fresh[:MAX_SERVERS]))}")
    exportable.sort(key=lambda x: x.get("ping") or 99999)

    database["servers"] = exportable  # в базе остаются только рабочие из подписки
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
        "fresh": len(fresh),
        "old": len(old),
        "subscription": len(exportable),
        "removed_dead": removed_dead,
        "duration_seconds": round(time.time() - started, 2)
    }
    save_json(STATS_FILE, stats)
    print("\n[OK] Parser finished successfully.")


if __name__ == "__main__":
    main()
