#!/usr/bin/env python3
# xkeen-ik: web panel for SKeen + sing-box-lx on Keenetic (Entware). Python stdlib only.
import base64, copy, difflib, hashlib, hmac, io, ipaddress, json, os, re, secrets, shutil, subprocess, sys
import tarfile, tempfile, threading, time, urllib.parse, urllib.request, zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

VERSION = "0.1.1"
REPO = "icomium/xkeen-ik"
SKEEN_REPO = "jinndi/SKeen"
CORE_REPO = "Leadaxe/sing-box-lx"
HOME = os.environ.get("XIK_HOME", "/opt/etc/xkeen-ik")
SKEEN_DIR = os.environ.get("XIK_SKEEN_DIR", "/opt/etc/skeen")
SKEEN_BIN = os.environ.get("XIK_SKEEN_BIN", "/opt/bin/skeen")
CORE = os.environ.get("XIK_CORE", "/opt/bin/sing-box-lx")
INIT_PATH = os.environ.get("XIK_INIT", "/opt/etc/init.d/S98xkeen-ik")
BIN_LINK = os.environ.get("XIK_BIN", "/opt/bin/xkeen-ik")
SELF_PATH = os.path.abspath(__file__)
CONFIG = os.path.join(SKEEN_DIR, "config.json")
SKEEN_JSON = os.path.join(SKEEN_DIR, "skeen.json")
STATE_PATH = os.path.join(HOME, "state.json")
BACKUPS = os.path.join(HOME, "backups")
PREFIX = "xik\u00b7"

LOCK = threading.RLock()
TASK = {"name": "", "running": False, "log": [], "ok": None}
DEFAULT_SETTINGS = {
    "token": "", "port": 8090, "bind": "0.0.0.0", "proxy": "", "self_channel": "release",
    "auto_apply": True, "check_hours": 6, "auto_update": {"skeen": False, "core": False},
    "groups": ["\U0001F30D Auto", "\U0001F30D Proxy"], "placeholders": ["\U0001F512 TROYAN"],
    "direct_out": "\U0001F50C DIRECT", "proxy_out": "\U0001F30D Proxy",
    "dns_direct": "dns_direct", "dns_fakeip": "dns_fakeip",
}
STATE = {}


class XikError(Exception):
    pass


# ---------- files / state ----------
def atomic_write(path, data, mode=None):
    if isinstance(data, str):
        data = data.encode("utf-8")
    d = os.path.dirname(path) or "."
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".xik-", dir=d)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        if mode is not None:
            os.chmod(tmp, mode)
        os.replace(tmp, path)
    except Exception:
        if os.path.exists(tmp):
            os.remove(tmp)
        raise


def load_state():
    global STATE
    try:
        with open(STATE_PATH, encoding="utf-8") as f:
            STATE = json.load(f)
    except (OSError, ValueError):
        STATE = {}
    s = STATE.setdefault("settings", {})
    for k, v in DEFAULT_SETTINGS.items():
        s.setdefault(k, copy.deepcopy(v))
    if not s["token"]:
        s["token"] = secrets.token_urlsafe(18)
    STATE.setdefault("subs", [])
    STATE.setdefault("rules", [])
    STATE.setdefault("applied", {"route": [], "dns": []})
    STATE.setdefault("updates", {})
    save_state()


def save_state():
    atomic_write(STATE_PATH, json.dumps(STATE, indent=1, ensure_ascii=False), 0o600)


def S(key):
    return STATE["settings"][key]


def run(cmd, timeout=60):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, stdin=subprocess.DEVNULL,
                           cwd=SKEEN_DIR if os.path.isdir(SKEEN_DIR) else None)
        return p.returncode, (p.stdout + p.stderr)[-4000:]
    except Exception as e:
        return 127, str(e)


def http_open(url, timeout=30):
    handlers = []
    if S("proxy"):
        handlers.append(urllib.request.ProxyHandler({"http": S("proxy"), "https": S("proxy")}))
    req = urllib.request.Request(url, headers={"User-Agent": "xkeen-ik/" + VERSION})
    return urllib.request.build_opener(*handlers).open(req, timeout=timeout)


def http_get(url, timeout=30, limit=20 * 1024 * 1024):
    with http_open(url, timeout) as r:
        return r.read(limit), dict(r.headers)


def http_download(url, path, timeout=60):
    with http_open(url, timeout) as r, open(path, "wb") as f:
        shutil.copyfileobj(r, f, 1 << 16)


def gh_json(url):
    return json.loads(http_get(url)[0].decode())


def vkey(v):
    return tuple(int(x) for x in re.findall(r"\d+", v or ""))


# ---------- subscription parsing (3x-ui) ----------
def b64d(s):
    s = s.strip().replace("-", "+").replace("_", "/")
    return base64.b64decode(s + "=" * (-len(s) % 4))


def first(q, k, d=""):
    v = q.get(k)
    return v[0] if v else d


def mk_tls(q, sni_default, force=False):
    sec = first(q, "security")
    if sec not in ("tls", "reality") and not force:
        return None
    t = {"enabled": True, "server_name": first(q, "sni") or first(q, "host") or sni_default}
    if first(q, "alpn"):
        t["alpn"] = first(q, "alpn").split(",")
    if first(q, "allowInsecure") in ("1", "true") or first(q, "insecure") in ("1", "true"):
        t["insecure"] = True
    fp = first(q, "fp")
    if fp or sec == "reality":
        t["utls"] = {"enabled": True, "fingerprint": fp or "chrome"}
    if sec == "reality":
        t["reality"] = {"enabled": True, "public_key": first(q, "pbk"), "short_id": first(q, "sid")}
    return t


def mk_transport(q):
    net = first(q, "type") or first(q, "net") or "tcp"
    host, path = first(q, "host"), first(q, "path")
    if net == "ws":
        t = {"type": "ws", "path": path or "/"}
        if host:
            t["headers"] = {"Host": host}
        return net, t
    if net == "grpc":
        return net, {"type": "grpc", "service_name": first(q, "serviceName") or path}
    if net == "httpupgrade":
        t = {"type": "httpupgrade", "path": path or "/"}
        if host:
            t["host"] = host
        return net, t
    if net == "xhttp":
        t = {"type": "xhttp"}
        if host:
            t["host"] = host
        if path:
            t["path"] = path
        mode = first(q, "mode")
        if mode and mode != "auto":
            t["mode"] = mode
        return net, t
    if net in ("h2", "http"):
        t = {"type": "http", "path": path or "/"}
        if host:
            t["host"] = [host]
        return net, t
    return net, None


def parse_link(link):
    link = link.strip()
    scheme = link.split("://", 1)[0].lower()
    if scheme == "vmess":
        d = json.loads(b64d(link[8:]).decode())
        q = {k: [str(v)] for k, v in d.items() if v not in (None, "")}
        if str(d.get("tls", "")).lower() in ("tls", "1", "true"):
            q["security"] = ["tls"]
        o = {"type": "vmess", "tag": d.get("ps") or d["add"], "server": d["add"], "server_port": int(d["port"]),
             "uuid": d["id"], "alter_id": int(d.get("aid") or 0), "security": d.get("scy") or "auto"}
        _, tr = mk_transport(q)
        tls = mk_tls(q, d["add"])
        if tls:
            o["tls"] = tls
        if tr:
            o["transport"] = tr
        return o
    if scheme == "ss":
        rest, name = (link[5:].split("#", 1) + [""])[:2]
        rest = rest.split("?", 1)[0]
        if "@" in rest:
            ui, hp = rest.rsplit("@", 1)
            ui = urllib.parse.unquote(ui)
            if ":" not in ui:
                ui = b64d(ui).decode()
        else:
            ui, hp = b64d(rest).decode().rsplit("@", 1)
        method, pw = ui.split(":", 1)
        host, port = hp.rsplit(":", 1)
        return {"type": "shadowsocks", "tag": urllib.parse.unquote(name) or host, "server": host.strip("[]"),
                "server_port": int(port), "method": method, "password": pw}
    if scheme in ("vless", "trojan"):
        u = urllib.parse.urlparse(link)
        q = urllib.parse.parse_qs(u.query)
        name = urllib.parse.unquote(u.fragment) or "%s:%s" % (u.hostname, u.port)
        o = {"type": scheme, "tag": name, "server": u.hostname, "server_port": int(u.port)}
        net, tr = mk_transport(q)
        if scheme == "vless":
            o["uuid"] = urllib.parse.unquote(u.username)
            if first(q, "flow") and net != "xhttp":
                o["flow"] = first(q, "flow")
            o["packet_encoding"] = "xudp"
            tls = mk_tls(q, u.hostname)
        else:
            o["password"] = urllib.parse.unquote(u.username)
            tls = mk_tls(q, u.hostname, force=first(q, "security") != "none")
        if tls:
            o["tls"] = tls
        if tr:
            o["transport"] = tr
        return o
    raise ValueError("unsupported scheme " + scheme)


def decode_sub(body):
    txt = body.decode("utf-8", "ignore").strip()
    if txt[:1] in "{[":
        raise XikError("JSON-подписка не поддерживается: включите в 3x-ui обычную (base64) подписку")
    if "://" not in txt.split("\n", 1)[0]:
        try:
            txt = b64d(txt).decode("utf-8", "ignore")
        except Exception:
            raise XikError("не удалось декодировать подписку (ни ссылки, ни base64)")
    nodes, bad, seen = [], 0, set()
    for line in re.split(r"[\r\n]+", txt):
        line = line.strip()
        if not line:
            continue
        try:
            o = parse_link(line)
        except Exception:
            bad += 1
            continue
        base = PREFIX + str(o["tag"]).strip()
        tag, i = base, 2
        while tag in seen:
            tag, i = "%s #%d" % (base, i), i + 1
        seen.add(tag)
        o["tag"] = tag
        nodes.append(o)
    return nodes, bad


def refresh_sub(sub):
    sub["last_check"] = int(time.time())
    try:
        body, hdr = http_get(sub["url"], 30, 5 * 1024 * 1024)
        nodes, bad = decode_sub(body)
        if not nodes:
            raise XikError("в подписке нет поддерживаемых узлов (пропущено: %d)" % bad)
    except Exception as e:
        sub["status"], sub["error"] = "dead", str(e)
        save_state()
        return False
    h = hashlib.sha1(json.dumps(nodes, sort_keys=True).encode()).hexdigest()
    changed = h != sub.get("hash")
    sub.update(status="alive", error="", last_ok=sub["last_check"], count=len(nodes), skipped=bad, hash=h,
               nodes=nodes, info=hdr.get("subscription-userinfo", ""))
    save_state()
    return changed


# ---------- user rules + config building ----------
def classify(v):
    v = v.strip().lower()
    if v.startswith("full:"):
        return "domain", v[5:]
    if v.startswith("keyword:"):
        return "domain_keyword", v[8:]
    if "://" in v:
        v = urllib.parse.urlparse(v).hostname or v
    try:
        ipaddress.ip_network(v, strict=False)
        return "ip_cidr", v
    except ValueError:
        pass
    v = v.lstrip("*").lstrip(".")
    try:
        v = v.encode("idna").decode()
    except UnicodeError:
        raise XikError("некорректное имя: " + v)
    if not re.fullmatch(r"[a-z0-9_]([a-z0-9_.\-]*[a-z0-9_])?", v):
        raise XikError("некорректное имя или IP: " + v)
    return "domain_suffix", v


def rules_to_sing(rules):
    groups = []
    for r in rules:
        key, val = classify(r["value"])
        k = (key, r["action"])
        if groups and groups[-1][0] == k:
            if val not in groups[-1][1]:
                groups[-1][1].append(val)
        else:
            groups.append((k, [val]))
    route, dns = [], []
    for (key, action), vals in groups:
        out = S("direct_out") if action == "direct" else S("proxy_out")
        route.append({key: vals, "outbound": out})
        if key != "ip_cidr":
            if action == "direct":
                dns.append({key: vals, "server": S("dns_direct")})
            else:
                dns.append({key: vals, "server": S("dns_fakeip"), "rewrite_ttl": 300})
    return route, dns


def strip_applied(cfg, applied):
    for lst, key in ((cfg.get("route", {}).get("rules"), "route"), (cfg.get("dns", {}).get("rules"), "dns")):
        if lst is None:
            continue
        for r in applied.get(key, []):
            if r in lst:
                lst.remove(r)


def inject_nodes(cfg, nodes):
    outs = cfg.setdefault("outbounds", [])
    old = {o.get("tag") for o in outs if str(o.get("tag", "")).startswith(PREFIX)}
    outs[:] = [o for o in outs if o.get("tag") not in old]
    ph = set(S("placeholders"))
    for o in outs:
        if isinstance(o.get("outbounds"), list):
            o["outbounds"] = [t for t in o["outbounds"] if t not in old and not (nodes and t in ph)]
            if nodes and o.get("default") in ph:
                o.pop("default")
            if o.get("default") in old:
                o.pop("default")
    if not nodes:
        return
    tags = [n["tag"] for n in nodes]
    outs.extend(copy.deepcopy(nodes))
    for o in outs:
        if o.get("tag") in S("groups") and o.get("type") in ("selector", "urltest"):
            lst = o.setdefault("outbounds", [])
            lst.extend(t for t in tags if t not in lst)
    refs = set()
    for o in outs:
        refs.update(o.get("outbounds") or [])
        if o.get("detour"):
            refs.add(o["detour"])
    outs[:] = [o for o in outs if not (o.get("tag") in ph and o["tag"] not in refs)]


def insert_rules(lst, new, pred, fallback):
    idx = next((i for i, r in enumerate(lst) if pred(r)), fallback(lst))
    lst[idx:idx] = new


def build_config(base):
    cfg = copy.deepcopy(base)
    nodes = []
    for s in STATE["subs"]:
        if s.get("enabled", True):
            nodes += s.get("nodes", [])
    seen, uniq = set(), []
    for n in nodes:
        if n["tag"] not in seen:
            seen.add(n["tag"])
            uniq.append(n)
    inject_nodes(cfg, uniq)
    route, dns = rules_to_sing(STATE["rules"])
    applied = {"route": [], "dns": []}
    if route:
        rr = cfg.setdefault("route", {}).setdefault("rules", [])
        insert_rules(rr, route, lambda r: "rule_set" in r,
                     lambda l: next((i + 1 for i in range(len(l) - 1, -1, -1) if l[i].get("action") == "hijack-dns"), 0))
        applied["route"] = route
    servers = {x.get("tag") for x in cfg.get("dns", {}).get("servers", [])}
    dns = [r for r in dns if r["server"] in servers]
    if dns:
        dr = cfg.setdefault("dns", {}).setdefault("rules", [])
        insert_rules(dr, dns, lambda r: "rule_set" in r or "domain_keyword" in r or "clash_mode" in r, lambda l: 0)
        applied["dns"] = dns
    return cfg, applied


def detect_applied(cfg):
    route, dns = rules_to_sing(STATE["rules"])
    have_r = cfg.get("route", {}).get("rules", [])
    have_d = cfg.get("dns", {}).get("rules", [])
    return {"route": [r for r in route if r in have_r], "dns": [r for r in dns if r in have_d]}


def read_config():
    try:
        with open(CONFIG, encoding="utf-8") as f:
            return json.load(f)
    except OSError as e:
        raise XikError("нет %s: %s" % (CONFIG, e))
    except ValueError as e:
        raise XikError("config.json не является чистым JSON (комментарии?): %s" % e)


def compute():
    cur = read_config()
    base = copy.deepcopy(cur)
    strip_applied(base, STATE["applied"])
    new, applied = build_config(base)
    return cur, new, applied


def dumps(c):
    return json.dumps(c, indent=2, ensure_ascii=False) + "\n"


def preview():
    cur, new, _ = compute()
    d = list(difflib.unified_diff(dumps(cur).splitlines(), dumps(new).splitlines(), "config.json", "config.json (new)", lineterm="", n=2))
    return {"changed": bool(d), "diff": "\n".join(d[:600]) + ("\n... (обрезано)" if len(d) > 600 else "")}


# ---------- backup / apply / rollback ----------
def backup(label):
    name = time.strftime("%Y%m%d-%H%M%S")
    d = os.path.join(BACKUPS, name)
    n = 1
    while os.path.exists(d):
        n += 1
        d = os.path.join(BACKUPS, "%s-%d" % (name, n))
    os.makedirs(d)
    for p in (CONFIG, SKEEN_JSON):
        if os.path.exists(p):
            shutil.copy2(p, os.path.join(d, os.path.basename(p)))
    atomic_write(os.path.join(d, "meta.json"), json.dumps({"label": label, "ts": int(time.time()), "applied": STATE["applied"]}))
    for old in sorted(os.listdir(BACKUPS))[:-30]:
        shutil.rmtree(os.path.join(BACKUPS, old), ignore_errors=True)
    return os.path.basename(d)


def list_backups():
    out = []
    if os.path.isdir(BACKUPS):
        for n in sorted(os.listdir(BACKUPS), reverse=True):
            try:
                with open(os.path.join(BACKUPS, n, "meta.json")) as f:
                    m = json.load(f)
            except (OSError, ValueError):
                m = {}
            out.append({"name": n, "label": m.get("label", ""), "ts": m.get("ts", 0)})
    return out


def core_running():
    base = os.path.basename(CORE)
    try:
        for pid in os.listdir("/proc"):
            if pid.isdigit():
                try:
                    with open("/proc/%s/cmdline" % pid, "rb") as f:
                        argv0 = f.read().split(b"\0")[0].decode("utf-8", "ignore")
                except OSError:
                    continue
                if os.path.basename(argv0) == base:
                    return True
    except OSError:
        pass
    return False


def reload_core(restart=False):
    if not os.path.exists(SKEEN_BIN):
        return False, "skeen не найден: " + SKEEN_BIN
    cmd = "restart" if (restart and core_running()) else ("reload" if core_running() else "start")
    rc, out = run([SKEEN_BIN, cmd], 120)
    time.sleep(3)
    ok = rc == 0 and core_running()
    return ok, "skeen %s: rc=%s %s" % (cmd, rc, out.strip()[-500:])


def check_config_file(path, core=None):
    rc, out = run([core or CORE, "check", "-c", path, "-D", SKEEN_DIR], 60)
    if rc != 0:
        raise XikError("sing-box check: " + out.strip()[-800:])


def apply_config(new, applied, label):
    with LOCK:
        tmp = os.path.join(SKEEN_DIR, ".xik-new.json")
        atomic_write(tmp, dumps(new))
        try:
            check_config_file(tmp)
        except Exception:
            os.remove(tmp)
            raise
        bname = backup(label)
        old_applied = STATE["applied"]
        os.replace(tmp, CONFIG)
        ok, msg = reload_core()
        if not ok:
            restore(bname, reload=True)
            STATE["applied"] = old_applied
            save_state()
            raise XikError("перезапуск не удался, выполнен откат к %s. %s" % (bname, msg))
        STATE["applied"] = applied
        save_state()
        return {"backup": bname, "msg": msg}


def restore(name, reload=True):
    d = os.path.join(BACKUPS, os.path.basename(name))
    if not os.path.isdir(d):
        raise XikError("нет такого бэкапа")
    with LOCK:
        for fn in ("config.json", "skeen.json"):
            p = os.path.join(d, fn)
            if os.path.exists(p):
                with open(p, "rb") as f:
                    atomic_write(os.path.join(SKEEN_DIR, fn), f.read())
        try:
            with open(os.path.join(d, "meta.json")) as f:
                STATE["applied"] = json.load(f).get("applied", STATE["applied"])
        except (OSError, ValueError):
            pass
        save_state()
        return reload_core(restart=True)[1] if reload else ""


def apply_now(label="apply"):
    _, new, applied = compute()
    return apply_config(new, applied, label)


# ---------- SKeen settings ----------
def skeen_tune():
    if not os.path.exists(SKEEN_JSON):
        raise XikError("нет %s: сначала установите SKeen" % SKEEN_JSON)
    try:
        with open(SKEEN_JSON, encoding="utf-8") as f:
            j = json.load(f)
    except ValueError as e:
        raise XikError("skeen.json не является чистым JSON: %s" % e)
    j2 = copy.deepcopy(j)
    sv = j2.setdefault("services", {}).setdefault("api", {})
    sv["auto_start"], sv["dashboard"] = 0, 0
    up = j2.setdefault("update", {})
    up.setdefault("skeen", {}).update(enabled=0, api=0)
    up.setdefault("singbox", {})["enabled"] = 0
    ex = j2.setdefault("singbox", {}).setdefault("external", {})
    ex["enabled"], ex["path"] = 1, CORE
    if j2 != j:
        backup("pre-skeen-tune")
        atomic_write(SKEEN_JSON, json.dumps(j2, indent=2, ensure_ascii=False) + "\n")
    pidf = "/tmp/run/skeen-api.pid"
    try:
        with open(pidf) as f:
            os.kill(int(f.read().strip()), 15)
    except (OSError, ValueError):
        pass
    return j2 != j


# ---------- updates ----------
def skeen_version():
    if not os.path.exists(SKEEN_BIN):
        return ""
    rc, out = run([SKEEN_BIN, "version"], 20)
    m = re.search(r"\d+\.\d+(?:\.\d+)*", re.sub(r"\x1b\[[0-9;]*m", "", out))
    return m.group(0) if m else ""


def core_info():
    if not os.path.exists(CORE):
        return {"version": "", "xhttp": False}
    rc, out = run([CORE, "version"], 20)
    m = re.search(r"version\s+(\S+)", out)
    return {"version": m.group(1) if m else "", "xhttp": "with_xhttp" in out}


def core_arch():
    m = os.uname().machine.lower()
    if m in ("aarch64", "arm64"):
        return "arm64"
    if m.startswith("armv7") or m in ("armv8l", "armhf"):
        return "armv7"
    if m in ("x86_64", "amd64"):
        return "amd64"
    if m.startswith("mips"):
        return "mipsle-softfloat" if sys.byteorder == "little" else "mips-softfloat"
    if m in ("i386", "i686"):
        return "386"
    if m.startswith("riscv64"):
        return "riscv64"
    raise XikError("неизвестная архитектура " + m)


def check_updates():
    u = STATE["updates"]
    u["checked"] = int(time.time())
    for key, repo in (("skeen", SKEEN_REPO), ("core", CORE_REPO)):
        try:
            tag = gh_json("https://api.github.com/repos/%s/releases/latest" % repo)["tag_name"]
            cur = skeen_version() if key == "skeen" else core_info()["version"]
            u[key] = {"latest": tag, "current": cur, "available": bool(cur) and vkey(tag) > vkey(cur) or not cur, "error": ""}
        except Exception as e:
            u[key] = {"latest": "", "current": "", "available": False, "error": str(e)}
    try:
        rel = gh_json("https://api.github.com/repos/%s/releases/latest" % REPO)
        main_sha = gh_json("https://api.github.com/repos/%s/commits/main" % REPO)["sha"][:7]
        u["self"] = {"current": VERSION, "latest": rel["tag_name"], "main_sha": main_sha,
                     "available": vkey(rel["tag_name"]) > vkey(VERSION), "error": ""}
    except Exception as e:
        u["self"] = {"current": VERSION, "latest": "", "available": False, "error": str(e)}
    save_state()


def tmpdir(near):
    d = os.path.join(os.path.dirname(near) if near else HOME, ".xik-tmp")
    shutil.rmtree(d, ignore_errors=True)
    os.makedirs(d)
    return d


def update_core(log):
    arch = core_arch()
    rel = gh_json("https://api.github.com/repos/%s/releases/latest" % CORE_REPO)
    tag = rel["tag_name"]
    ver = tag.lstrip("v")
    name = "sing-box-%s-linux-%s.tar.gz" % (ver, arch)
    assets = {a["name"]: a["browser_download_url"] for a in rel["assets"]}
    if name not in assets:
        raise XikError("в релизе %s нет файла %s" % (tag, name))
    free = shutil.disk_usage(os.path.dirname(CORE)).free
    if free < 200 * 1024 * 1024:
        raise XikError("мало места рядом с %s: %d МБ (нужно ~200 МБ)" % (CORE, free >> 20))
    tmp = tmpdir(CORE)
    try:
        log("скачиваю " + name)
        arc = os.path.join(tmp, name)
        http_download(assets[name], arc, 120)
        if "SHA256SUMS" in assets:
            sums = http_get(assets["SHA256SUMS"])[0].decode()
            want = next((l.split()[0] for l in sums.splitlines() if l.strip().endswith(name)), "")
            h = hashlib.sha256()
            with open(arc, "rb") as f:
                for chunk in iter(lambda: f.read(1 << 20), b""):
                    h.update(chunk)
            if want and h.hexdigest() != want:
                raise XikError("SHA256 не совпал")
            log("SHA256 проверен" if want else "SHA256 для файла не найден в SHA256SUMS")
        new = os.path.join(tmp, "core.new")
        with tarfile.open(arc) as t:
            m = next((m for m in t.getmembers() if m.isfile() and os.path.basename(m.name) == "sing-box"), None)
            if not m:
                raise XikError("в архиве нет бинарника sing-box")
            with t.extractfile(m) as src, open(new, "wb") as dst:
                shutil.copyfileobj(src, dst, 1 << 16)
        os.remove(arc)
        os.chmod(new, 0o755)
        rc, out = run([new, "version"], 30)
        if rc != 0 or "with_xhttp" not in out:
            raise XikError("новое ядро не запускается или без with_xhttp: " + out.strip()[-300:])
        if os.path.exists(CONFIG):
            check_config_file(CONFIG, new)
            log("текущий config.json проходит check новым ядром")
        had = os.path.exists(CORE)
        if had:
            shutil.copy2(CORE, CORE + ".bak")
        os.replace(new, CORE)
        log("ядро установлено: " + tag)
        if had and os.path.exists(SKEEN_BIN) and core_running():
            ok, msg = reload_core(restart=True)
            log(msg)
            if not ok:
                os.replace(CORE + ".bak", CORE)
                reload_core(restart=True)
                raise XikError("ядро не стартовало, возвращена прежняя версия")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def update_skeen(log):
    before_core = core_info()["version"]
    tmp = tmpdir(HOME + "/x")
    try:
        p = os.path.join(tmp, "skeen-install.sh")
        http_download("https://github.com/%s/releases/latest/download/skeen" % SKEEN_REPO, p)
        backup("pre-skeen-update")
        log("запускаю установщик SKeen (версия до: %s)" % skeen_version())
        rc, out = run(["sh", p], 300)
        log(out.strip()[-600:])
        if rc != 0:
            raise XikError("установщик SKeen вернул %s" % rc)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    skeen_tune()
    log("версия после: %s; ядро: %s -> %s" % (skeen_version(), before_core, core_info()["version"]))


def update_self(log, channel):
    if channel == "main":
        url = "https://codeload.github.com/%s/tar.gz/refs/heads/main" % REPO
    else:
        url = gh_json("https://api.github.com/repos/%s/releases/latest" % REPO)["tarball_url"]
    tmp = tmpdir(HOME + "/x")
    try:
        arc = os.path.join(tmp, "src.tgz")
        http_download(url, arc)
        with tarfile.open(arc) as t:
            m = next((m for m in t.getmembers() if m.isfile() and m.name.count("/") == 1 and m.name.endswith("/xkeen-ik.py")), None)
            if not m:
                raise XikError("в архиве нет xkeen-ik.py")
            data = t.extractfile(m).read()
        compile(data, "xkeen-ik.py", "exec")
        shutil.copy2(SELF_PATH, SELF_PATH + ".bak")
        atomic_write(SELF_PATH, data, 0o755)
        log("панель обновлена (%s), перезапуск" % channel)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    threading.Timer(1.5, lambda: os.execv(sys.executable, [sys.executable, SELF_PATH] + sys.argv[1:])).start()


def start_task(name, fn):
    with LOCK:
        if TASK["running"]:
            raise XikError("уже выполняется: " + TASK["name"])
        TASK.update(name=name, running=True, log=[], ok=None)

    def work():
        try:
            fn(lambda m: TASK["log"].append(str(m)))
            TASK["ok"] = True
        except Exception as e:
            TASK["log"].append("ОШИБКА: %s" % e)
            TASK["ok"] = False
        finally:
            TASK["running"] = False

    threading.Thread(target=work, daemon=True).start()


# ---------- export / import ----------
def export_zip():
    buf = io.BytesIO()
    st = copy.deepcopy(STATE)
    st["settings"].pop("token", None)
    st["applied"] = {"route": [], "dns": []}
    st.pop("updates", None)
    for s in st["subs"]:
        s.pop("nodes", None)
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for p in (SKEEN_JSON, CONFIG):
            if os.path.exists(p):
                z.write(p, os.path.basename(p))
        z.writestr("xkeen-ik.json", json.dumps(st, indent=1, ensure_ascii=False))
    return buf.getvalue()


def import_blob(kind, data):
    if kind == "config":
        try:
            new = json.loads(data.decode("utf-8"))
        except ValueError as e:
            raise XikError("не JSON: %s" % e)
        return apply_config(new, detect_applied(new), "import config.json")
    if kind == "skeen":
        try:
            json.loads(data.decode("utf-8"))
        except ValueError as e:
            raise XikError("не JSON: %s" % e)
        with LOCK:
            b = backup("import skeen.json")
            atomic_write(SKEEN_JSON, data)
            skeen_tune()
        return {"backup": b, "msg": "skeen.json записан; примените skeen restart"}
    if kind == "zip":
        try:
            z = zipfile.ZipFile(io.BytesIO(data))
        except zipfile.BadZipFile:
            raise XikError("это не ZIP")
        names = {i.filename: i for i in z.infolist() if i.file_size < 30 * 1024 * 1024}
        res = []
        if "skeen.json" in names:
            res.append(import_blob("skeen", z.read("skeen.json")))
        if "xkeen-ik.json" in names:
            st = json.loads(z.read("xkeen-ik.json").decode("utf-8"))
            with LOCK:
                STATE["subs"] = st.get("subs", [])
                STATE["rules"] = st.get("rules", [])
                tok = S("token")
                STATE["settings"].update({k: v for k, v in st.get("settings", {}).items() if k != "token"})
                STATE["settings"]["token"] = tok
                save_state()
            res.append({"msg": "подписки, правила и настройки панели импортированы"})
        if "config.json" in names:
            res.append(import_blob("config", z.read("config.json")))
        if not res:
            raise XikError("в ZIP нет skeen.json / config.json / xkeen-ik.json")
        return {"parts": res}
    raise XikError("неизвестный тип")


# ---------- API ----------
def public_state():
    subs = [{k: v for k, v in s.items() if k != "nodes"} for s in STATE["subs"]]
    st = {k: v for k, v in STATE["settings"].items() if k != "token"}
    return {"version": VERSION, "settings": st, "subs": subs, "rules": STATE["rules"], "updates": STATE["updates"],
            "skeen": {"version": skeen_version(), "installed": os.path.exists(SKEEN_BIN)},
            "core": dict(core_info(), running=core_running(), path=CORE), "task": TASK,
            "backups": list_backups(), "arch": os.uname().machine}


def new_id():
    return secrets.token_hex(4)


def find(lst, i):
    for x in lst:
        if x["id"] == i:
            return x
    raise XikError("не найдено")


def api(method, path, q, body, raw):
    with LOCK:
        if path == "state":
            return public_state()
        if path == "sub/add":
            url = (body.get("url") or "").strip()
            if not url.startswith(("http://", "https://")):
                raise XikError("нужен URL подписки http(s)://")
            sub = {"id": new_id(), "name": body.get("name") or urllib.parse.urlparse(url).hostname, "url": url,
                   "interval_min": max(5, int(body.get("interval_min") or 360)), "enabled": True, "nodes": []}
            STATE["subs"].append(sub)
            ch = refresh_sub(sub)
            return {"ok": sub["status"] == "alive", "status": sub["status"], "error": sub.get("error", ""), "count": sub.get("count", 0), "changed": ch}
        if path == "sub/del":
            STATE["subs"].remove(find(STATE["subs"], body["id"]))
            save_state()
            return {"ok": True}
        if path == "sub/edit":
            s = find(STATE["subs"], body["id"])
            if "interval_min" in body:
                s["interval_min"] = max(5, int(body["interval_min"]))
            if "enabled" in body:
                s["enabled"] = bool(body["enabled"])
            save_state()
            return {"ok": True}
        if path == "sub/refresh":
            s = find(STATE["subs"], body["id"])
            ch = refresh_sub(s)
            res = {"status": s["status"], "error": s.get("error", ""), "count": s.get("count", 0), "changed": ch}
            if ch and S("auto_apply") and body.get("apply", True):
                res["apply"] = apply_now("subscription refresh")
            return res
        if path == "rule/add":
            classify(body.get("value", ""))
            if body.get("action") not in ("direct", "vpn"):
                raise XikError("action: direct или vpn")
            STATE["rules"].append({"id": new_id(), "value": body["value"].strip(), "action": body["action"], "note": body.get("note", "")})
            save_state()
            return {"ok": True}
        if path == "rule/del":
            STATE["rules"].remove(find(STATE["rules"], body["id"]))
            save_state()
            return {"ok": True}
        if path == "rule/move":
            r = find(STATE["rules"], body["id"])
            i = STATE["rules"].index(r)
            j = i + (-1 if body.get("dir") == "up" else 1)
            if 0 <= j < len(STATE["rules"]):
                STATE["rules"][i], STATE["rules"][j] = STATE["rules"][j], STATE["rules"][i]
                save_state()
            return {"ok": True}
        if path == "preview":
            return preview()
        if path == "apply":
            return apply_now("manual apply")
        if path == "restore":
            return {"msg": restore(body["name"])}
        if path == "settings":
            for k in ("proxy", "self_channel", "auto_apply", "check_hours", "groups", "placeholders", "direct_out", "proxy_out", "dns_direct", "dns_fakeip", "auto_update"):
                if k in body:
                    STATE["settings"][k] = body[k]
            save_state()
            return {"ok": True}
        if path == "skeen/tune":
            return {"changed": skeen_tune()}
        if path == "update/check":
            check_updates()
            return STATE["updates"]
        if path == "update/run":
            what = body.get("what")
            if what == "core":
                start_task("обновление sing-box-lx", update_core)
            elif what == "skeen":
                start_task("обновление SKeen", update_skeen)
            elif what == "self":
                ch = body.get("channel") or S("self_channel")
                start_task("обновление панели (%s)" % ch, lambda log: update_self(log, ch))
            else:
                raise XikError("what: core|skeen|self")
            return {"started": True}
        if path == "export":
            kind = q.get("kind", ["zip"])[0]
            if kind == "skeen":
                return ("skeen.json", open(SKEEN_JSON, "rb").read(), "application/json")
            if kind == "config":
                return ("config.json", open(CONFIG, "rb").read(), "application/json")
            return ("xkeen-ik-backup-%s.zip" % time.strftime("%Y%m%d-%H%M%S"), export_zip(), "application/zip")
        if path == "import":
            return import_blob(q.get("kind", [""])[0], raw)
    raise XikError("нет такого метода")


class Handler(BaseHTTPRequestHandler):
    server_version = "xkeen-ik"

    def log_message(self, *a):
        pass

    def send(self, code, data, ctype="application/json", extra=None):
        if not isinstance(data, bytes):
            data = json.dumps(data, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype + ("; charset=utf-8" if ctype.startswith("text") or ctype == "application/json" else ""))
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def authed(self, q):
        t = self.headers.get("X-Token") or (q.get("token") or [""])[0]
        return bool(t) and hmac.compare_digest(t.encode(), S("token").encode())

    def handle_any(self, method):
        u = urllib.parse.urlparse(self.path)
        q = urllib.parse.parse_qs(u.query)
        if method == "GET" and u.path in ("/", "/index.html"):
            return self.send(200, HTML.encode(), "text/html")
        if not u.path.startswith("/api/"):
            return self.send(404, {"error": "not found"})
        if not self.authed(q):
            return self.send(403, {"error": "неверный или отсутствующий token"})
        n = int(self.headers.get("Content-Length") or 0)
        if n > 60 * 1024 * 1024:
            return self.send(413, {"error": "слишком большой запрос"})
        raw = self.rfile.read(n) if n else b""
        body = {}
        if method == "POST" and raw and u.path != "/api/import":
            try:
                body = json.loads(raw.decode())
            except ValueError:
                return self.send(400, {"error": "bad json"})
        try:
            res = api(method, u.path[5:], q, body, raw)
        except XikError as e:
            return self.send(400, {"error": str(e)})
        except Exception as e:
            return self.send(500, {"error": "%s: %s" % (type(e).__name__, e)})
        if isinstance(res, tuple):
            return self.send(200, res[1], res[2], {"Content-Disposition": 'attachment; filename="%s"' % res[0]})
        self.send(200, res)

    def do_GET(self):
        self.handle_any("GET")

    def do_POST(self):
        self.handle_any("POST")


def scheduler():
    while True:
        time.sleep(30)
        try:
            now = time.time()
            for s in list(STATE["subs"]):
                if s.get("enabled", True) and now - s.get("last_check", 0) >= s.get("interval_min", 360) * 60:
                    with LOCK:
                        if refresh_sub(s) and S("auto_apply"):
                            try:
                                apply_now("auto: subscription " + s["name"])
                            except XikError as e:
                                s["error"] = "apply: %s" % e
                                save_state()
            if now - STATE["updates"].get("checked", 0) >= S("check_hours") * 3600:
                check_updates()
                u = STATE["updates"]
                if S("auto_update")["core"] and u.get("core", {}).get("available") and not TASK["running"]:
                    start_task("авто-обновление sing-box-lx", update_core)
                elif S("auto_update")["skeen"] and u.get("skeen", {}).get("available") and not TASK["running"]:
                    start_task("авто-обновление SKeen", update_skeen)
        except Exception as e:
            sys.stderr.write("scheduler: %s\n" % e)


INIT_SCRIPT = """#!/bin/sh
PY=$(command -v python3 || echo /opt/bin/python3)
APP=%s
PID=/opt/var/run/xkeen-ik.pid
LOG=/opt/var/log/xkeen-ik.log
running() { [ -f "$PID" ] && kill -0 "$(cat $PID)" 2>/dev/null; }
case "$1" in
  start)
    running && { echo "xkeen-ik already running"; exit 0; }
    [ -f "$LOG" ] && [ "$(wc -c < $LOG)" -gt 1048576 ] && : > "$LOG"
    "$PY" "$APP" serve >> "$LOG" 2>&1 </dev/null &
    echo $! > "$PID"; echo "xkeen-ik started" ;;
  stop) running && kill "$(cat $PID)"; rm -f "$PID"; echo "xkeen-ik stopped" ;;
  restart) "$0" stop; sleep 1; "$0" start ;;
  status) running && echo running || { echo stopped; exit 1; } ;;
  url) "$PY" "$APP" url ;;
  *) echo "usage: $0 {start|stop|restart|status|url}"; exit 1 ;;
esac
""" % SELF_PATH


def lan_ip():
    rc, out = run(["ip", "-4", "addr", "show", "br0"], 10)
    m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", out)
    return m.group(1) if m else "ROUTER_IP"


def show_url():
    load_state()
    print("http://%s:%s/?token=%s" % (lan_ip(), S("port"), S("token")))


def setup():
    os.makedirs(BACKUPS, exist_ok=True)
    os.makedirs("/opt/var/log", exist_ok=True)
    os.makedirs("/opt/var/run", exist_ok=True)
    load_state()
    try:
        print("skeen.json: %s" % ("изменён (внутреннее управление SKeen отключено)" if skeen_tune() else "уже настроен"))
    except XikError as e:
        print("ВНИМАНИЕ:", e)
    if not os.path.exists(CORE):
        print("устанавливаю sing-box-lx ...")
        try:
            update_core(print)
        except Exception as e:
            print("ВНИМАНИЕ: ядро не установлено (%s). Повторите в панели: Обновления -> sing-box-lx" % e)
    else:
        print("ядро уже есть:", core_info())
    atomic_write(INIT_PATH, INIT_SCRIPT, 0o755)
    print("автозапуск:", INIT_PATH)
    try:
        if os.path.lexists(BIN_LINK):
            os.remove(BIN_LINK)
        os.symlink(INIT_PATH, BIN_LINK)
        print("команда: xkeen-ik {start|stop|restart|status|url}")
    except OSError as e:
        print("ВНИМАНИЕ: не удалось создать %s (%s)" % (BIN_LINK, e))
    print("TOKEN=" + S("token"))


def serve():
    os.makedirs(BACKUPS, exist_ok=True)
    load_state()
    threading.Thread(target=scheduler, daemon=True).start()
    srv = ThreadingHTTPServer((S("bind"), int(S("port"))), Handler)
    srv.daemon_threads = True
    print("xkeen-ik %s on %s:%s" % (VERSION, S("bind"), S("port")), flush=True)
    srv.serve_forever()


HTML = r"""<!doctype html><html lang="ru"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>xkeen-ik</title>
<style>body{font:14px system-ui,sans-serif;margin:0;background:#14161a;color:#dcdfe4}header{display:flex;gap:6px;flex-wrap:wrap;padding:8px;background:#1d2026;position:sticky;top:0}
button,input,select,textarea{background:#262a31;color:#dcdfe4;border:1px solid #3a3f48;border-radius:5px;padding:6px 9px;font:inherit}button{cursor:pointer}button.on{background:#2f6fed;border-color:#2f6fed}button.danger{border-color:#a33}
main{padding:12px;max-width:980px;margin:auto}section{background:#1d2026;border-radius:8px;padding:12px;margin-bottom:12px}h3{margin:0 0 8px}table{width:100%;border-collapse:collapse}td,th{padding:5px;border-bottom:1px solid #2c3037;text-align:left;vertical-align:top}
pre{background:#0d0e10;padding:8px;border-radius:6px;overflow:auto;max-height:420px;white-space:pre-wrap}.ok{color:#5c5}.bad{color:#e55}.mut{color:#8a909b}.row{display:flex;gap:6px;flex-wrap:wrap;margin:6px 0}input.w{flex:1;min-width:180px}</style>
<header id="tabs"></header><main id="m"></main>
<script>
const T=new URLSearchParams(location.search).get('token')||localStorage.xt||'';localStorage.xt=T;
const $=(t,a,...c)=>{const e=document.createElement(t);for(const k in(a||{})){if(k.startsWith('on'))e[k]=a[k];else if(k==='cls')e.className=a[k];else e.setAttribute(k,a[k])}c.flat().forEach(x=>e.append(x instanceof Node?x:String(x??'')));return e};
async function api(p,b){const r=await fetch('/api/'+p,{method:b===undefined?'GET':'POST',headers:{'X-Token':T,'Content-Type':'application/json'},body:b===undefined?undefined:JSON.stringify(b)});const j=await r.json().catch(()=>({error:'bad response'}));if(!r.ok)throw new Error(j.error||r.status);return j}
let S={},tab='status',msg='';const TABS={status:'Статус',subs:'Подписки',rules:'Правила',apply:'Применение',upd:'Обновления',bk:'Бэкап и настройки'};
const ts=t=>t?new Date(t*1000).toLocaleString():'—';
async function act(fn){try{const r=await fn();msg=r&&(r.msg||r.error||(r.status?r.status+(r.error?': '+r.error:''):''))||'готово'}catch(e){msg='Ошибка: '+e.message}await load()}
async function load(){try{S=await api('state')}catch(e){document.getElementById('m').replaceChildren($('section',0,'Ошибка: '+e.message+'. Откройте страницу как /?token=ВАШ_ТОКЕН'));return}render()}
function render(){const t=document.getElementById('tabs');t.replaceChildren(...Object.keys(TABS).map(k=>$('button',{cls:k==tab?'on':'',onclick:()=>{tab=k;render()}},TABS[k])),$('span',{cls:'mut'},'xkeen-ik '+S.version));
const m=document.getElementById('m');m.replaceChildren(...(msg?[$('section',0,msg)]:[]),...({status,subs,rules,apply,upd,bk}[tab]()))}
function status(){const u=S.updates||{};return[$('section',0,$('h3',0,'Состояние'),$('div',0,'SKeen: ',S.skeen.installed?S.skeen.version||'установлен':'НЕ установлен'),$('div',0,'sing-box-lx: ',S.core.version||'не установлен',S.core.xhttp?' (XHTTP ✓)':' (XHTTP ✗)',' — ',S.core.running?$('b',{cls:'ok'},'работает'):$('b',{cls:'bad'},'остановлен')),$('div',{cls:'mut'},'Архитектура: '+S.arch+', путь ядра: '+S.core.path),$('div',0,'Подписок: '+S.subs.length+', правил: '+S.rules.length)),
...(S.task.name?[$('section',0,$('h3',0,'Задача: '+S.task.name+(S.task.running?' …':S.task.ok?' ✓':' ✗')),$('pre',0,S.task.log.join('\n')))]:[])]}
function subs(){const url=$('input',{cls:'w',placeholder:'https://panel:2096/sub/xxxx'}),nm=$('input',{placeholder:'имя'}),iv=$('input',{type:'number',value:360,style:'width:90px',title:'минут'});
return[$('section',0,$('h3',0,'Подписки 3x-ui'),$('div',{cls:'row'},nm,url,iv,$('button',{onclick:()=>act(()=>api('sub/add',{name:nm.value,url:url.value,interval_min:+iv.value}))},'Добавить')),
$('table',0,$('tr',0,...['Имя','Статус','Узлов','Проверка','Интервал, мин',''].map(x=>$('th',0,x))),...S.subs.map(s=>{const i=$('input',{type:'number',value:s.interval_min,style:'width:80px',onchange:()=>act(()=>api('sub/edit',{id:s.id,interval_min:+i.value}))});
return $('tr',0,$('td',0,s.name),$('td',0,$('b',{cls:s.status=='alive'?'ok':'bad'},s.status=='alive'?'жива':'недоступна'),s.error?$('div',{cls:'mut'},s.error):''),$('td',0,s.count??'—'),$('td',0,ts(s.last_check)),$('td',0,i),
$('td',0,$('button',{onclick:()=>act(()=>api('sub/refresh',{id:s.id}))},'Обновить'),' ',$('button',{cls:'danger',onclick:()=>confirm('Удалить?')&&act(()=>api('sub/del',{id:s.id}))},'×')))})),
$('p',{cls:'mut'},'Узлы попадают в группы sing-box (см. «Настройки»). После обновления подписки конфиг применяется автоматически (если включено).'))]}
function rules(){const v=$('input',{cls:'w',placeholder:'example.com, full:www.example.com, keyword:foo, 1.2.3.0/24'}),a=$('select',0,$('option',{value:'direct'},'Напрямую'),$('option',{value:'vpn'},'Через VPN')),n=$('input',{placeholder:'заметка'});
return[$('section',0,$('h3',0,'Свои правила (приоритет выше списков)'),$('div',{cls:'row'},v,a,n,$('button',{onclick:()=>act(()=>api('rule/add',{value:v.value,action:a.value,note:n.value}))},'Добавить')),
$('table',0,...S.rules.map(r=>$('tr',0,$('td',0,r.value),$('td',0,r.action=='direct'?'Напрямую':'Через VPN'),$('td',{cls:'mut'},r.note),$('td',0,$('button',{onclick:()=>act(()=>api('rule/move',{id:r.id,dir:'up'}))},'↑'),$('button',{onclick:()=>act(()=>api('rule/move',{id:r.id,dir:'down'}))},'↓'),$('button',{cls:'danger',onclick:()=>act(()=>api('rule/del',{id:r.id}))},'×'))))),
$('p',{cls:'mut'},'Домен без префикса = сам домен и все поддомены. Правила вступают в силу после «Применить».'))]}
function apply(){const pre=$('pre',0,'Нажмите «Показать изменения»');return[$('section',0,$('h3',0,'Безопасное применение'),$('p',{cls:'mut'},'preview → sing-box check → бэкап → атомарная запись → перезагрузка → откат при ошибке'),
$('div',{cls:'row'},$('button',{onclick:async()=>{try{const r=await api('preview',{});pre.textContent=r.changed?r.diff:'Изменений нет'}catch(e){pre.textContent=e.message}}},'Показать изменения'),$('button',{cls:'on',onclick:()=>act(()=>api('apply',{}))},'Применить')),pre)]}
function upd(){const u=S.updates||{};const row=(k,n)=>{const x=u[k]||{};return $('tr',0,$('td',0,n),$('td',0,x.current||'—'),$('td',0,x.latest||'—'),$('td',0,x.error?$('span',{cls:'bad'},x.error):x.available?$('b',{cls:'ok'},'есть обновление'):'актуально'),$('td',0,k=='self'?[$('button',{onclick:()=>act(()=>api('update/run',{what:k,channel:'release'}))},'из релиза'),' ',$('button',{onclick:()=>act(()=>api('update/run',{what:k,channel:'main'}))},'из main')]:$('button',{onclick:()=>act(()=>api('update/run',{what:k}))},'Обновить')))};
return[$('section',0,$('h3',0,'Обновления (независимые)'),$('div',{cls:'row'},$('button',{onclick:()=>act(()=>api('update/check',{}))},'Проверить сейчас'),$('span',{cls:'mut'},'проверено: '+ts(u.checked))),
$('table',0,$('tr',0,...['Компонент','Сейчас','Последняя','Статус',''].map(x=>$('th',0,x))),row('skeen','SKeen'),row('core','sing-box-lx'),row('self','xkeen-ik (панель)'))),
...(S.task.name?[$('section',0,$('h3',0,S.task.name+(S.task.running?' …':S.task.ok?' ✓':' ✗')),$('pre',0,S.task.log.join('\n')))]:[])]}
function bk(){const f=$('input',{type:'file'}),kind=$('select',0,$('option',{value:'zip'},'ZIP-бэкап'),$('option',{value:'config'},'config.json'),$('option',{value:'skeen'},'skeen.json'));const st=S.settings;
const px=$('input',{cls:'w',value:st.proxy,placeholder:'http://127.0.0.1:PORT (прокси для скачивания с GitHub, необязательно)'});
return[$('section',0,$('h3',0,'Экспорт / импорт'),$('div',{cls:'row'},...[['zip','ZIP'],['config','config.json'],['skeen','skeen.json']].map(([k,n])=>$('a',{href:'/api/export?kind='+k+'&token='+encodeURIComponent(T)},$('button',0,'⬇ '+n)))),
$('div',{cls:'row'},f,kind,$('button',{onclick:()=>f.files[0]&&act(async()=>{const r=await fetch('/api/import?kind='+kind.value,{method:'POST',headers:{'X-Token':T},body:await f.files[0].arrayBuffer()});const j=await r.json();if(!r.ok)throw new Error(j.error);return{msg:JSON.stringify(j)}})},'⬆ Импорт (config — через check и откат)'))),
$('section',0,$('h3',0,'Бэкапы'),$('table',0,...S.backups.slice(0,15).map(b=>$('tr',0,$('td',0,b.name),$('td',{cls:'mut'},b.label),$('td',0,$('button',{onclick:()=>confirm('Восстановить '+b.name+'?')&&act(()=>api('restore',{name:b.name}))},'Откатить')))))),
$('section',0,$('h3',0,'Настройки'),$('div',{cls:'row'},px,$('button',{onclick:()=>act(()=>api('settings',{proxy:px.value}))},'Сохранить')),
$('label',0,$('input',{type:'checkbox',...(st.auto_apply?{checked:''}:{}),onchange:e=>act(()=>api('settings',{auto_apply:e.target.checked}))}),' применять конфиг автоматически после обновления подписки'),
$('div',{cls:'row'},$('label',0,$('input',{type:'checkbox',...(st.auto_update.core?{checked:''}:{}),onchange:e=>act(()=>api('settings',{auto_update:{...st.auto_update,core:e.target.checked}}))}),' авто-обновление ядра'),$('label',0,$('input',{type:'checkbox',...(st.auto_update.skeen?{checked:''}:{}),onchange:e=>act(()=>api('settings',{auto_update:{...st.auto_update,skeen:e.target.checked}}))}),' авто-обновление SKeen')),
$('div',{cls:'row'},$('button',{onclick:()=>act(()=>api('skeen/tune',{}))},'Отключить штатное управление SKeen (повторно)')))]}
load();setInterval(()=>{if(S.task&&S.task.running)load()},3000);
</script></html>"""

if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "serve"
    if cmd == "setup":
        setup()
    elif cmd == "serve":
        serve()
    elif cmd == "url":
        show_url()
    else:
        print("usage: xkeen-ik.py [setup|serve|url]")
