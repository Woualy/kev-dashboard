#!/usr/bin/env python3
"""Génère les fichiers JSON du mission control (bibliothèque standard uniquement).
Usage : python scripts/build_data.py out
Sortie : feeds.json, kev.json, cve.json, history.json, meta.json
"""
import html, json, os, re, sys, time, urllib.request
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from zoneinfo import ZoneInfo

OUT = sys.argv[1] if len(sys.argv) > 1 else "out"
PREV = os.environ.get("PREV_BASE", "")  # URL raw de la branche « data » (reprise des données précédentes)
UA = "Mozilla/5.0 (compatible; mission-control-bot/1.0)"
GH = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/"
KEV = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEVM = "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json"
HIST = "https://cve.0xosprey.com/data.json"
EPSS = "https://api.first.org/data/v1/epss"  # probabilité d'exploitation à 30 jours (FIRST, publique)
KEV_IDS = set()
FEEDS = [  # mêmes id que le dashboard ; modifie cette liste pour ajouter des flux
    dict(id="fb", name="FrenchBreaches", url="https://frenchbreaches.com/feed.xml", lang="FR"),
    dict(id="1", name="CERT-FR – Alertes", url="https://www.cert.ssi.gouv.fr/alerte/feed/", lang="FR"),
    dict(id="2", name="CERT-FR – Avis", url="https://www.cert.ssi.gouv.fr/avis/feed/", lang="FR"),
    dict(id="3", name="Zataz", url="https://www.zataz.com/feed/", lang="FR"),
    dict(id="8", name="Cybermalveillance.gouv.fr", url="https://www.cybermalveillance.gouv.fr/feed/atom-flux-complet", lang="FR"),
    dict(id="6", name="The Hacker News", url="https://feeds.feedburner.com/TheHackersNews", lang="EN"),
    dict(id="7", name="BleepingComputer", url="https://www.bleepingcomputer.com/feed/", lang="EN"),
    dict(id="cti", name="CERT-FR – CTI", url="https://www.cert.ssi.gouv.fr/cti/feed/", lang="FR"),
    dict(id="act", name="CERT-FR – Actualités", url="https://www.cert.ssi.gouv.fr/actualite/feed/", lang="FR"),
    dict(id="enisa", name="ENISA", url="https://www.enisa.europa.eu/rss.xml", lang="EN"),
    dict(id="cnil", name="CNIL", url="https://www.cnil.fr/fr/rss.xml", lang="FR"),
    dict(id="isc", name="SANS ISC", url="https://isc.sans.edu/rssfeed_full.xml", lang="EN"),
]
STATUS = [  # météo Cloud & SaaS : flux publics d'état de service
    dict(id="m365", name="Microsoft 365", url="https://status.cloud.microsoft/", kind="rss", feed="https://status.cloud.microsoft/api/feed/mac"),
    dict(id="azure", name="Azure", url="https://azure.status.microsoft/en-us/status", kind="rss_active", feed="https://rssfeed.azure.status.microsoft/en-us/status/feed/"),
    dict(id="aws", name="AWS", url="https://health.aws.amazon.com/health/status", kind="rss", feed="https://status.aws.amazon.com/rss/all.rss"),
    dict(id="cloudflare", name="Cloudflare", url="https://www.cloudflarestatus.com/", kind="statuspage", feed="https://www.cloudflarestatus.com/api/v2/summary.json"),
    dict(id="ovh", name="OVHcloud", url="https://status.ovhcloud.com/", kind="statuspage", feed="https://status.ovhcloud.com/api/v2/summary.json",
         hint="pas de flux public vérifié : voir la page officielle"),
]
RANSOM = [  # (URL, tout est déjà filtré sur la France ?)
    ("https://api.ransomware.live/v2/recentvictims", False),
    ("https://api.ransomware.live/recentvictims", False),
    ("https://api.ransomware.live/v2/countryvictims/FR", True),
]


def get(url, headers=None, timeout=40):
    req = urllib.request.Request(url, headers={"User-Agent": UA, **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def prev(name):
    if not PREV:
        return None
    try:
        return json.loads(get(PREV + name, timeout=20))
    except Exception:
        return None


def ms(s):
    if not s:
        return 0
    try:
        d = parsedate_to_datetime(s)
    except Exception:
        try:
            d = datetime.fromisoformat(s.replace("Z", "+00:00"))
        except Exception:
            return 0
    if d.tzinfo is None:
        d = d.replace(tzinfo=timezone.utc)
    return int(d.timestamp() * 1000)


def plain(h, n=0):
    t = re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]+>", " ", h or ""))).strip()
    return t[:n].rsplit(" ", 1)[0] + "…" if n and len(t) > n else t


def zone(f):
    u = f["url"]
    if "cert.ssi.gouv.fr" in u:
        return "alerte" if "/alerte" in u else "cti" if "/cti" in u else "fr" if "/actualite" in u else "avis"
    if "frenchbreaches" in f["url"]:
        return "leak"
    return "fr" if f["lang"] == "FR" else "int"


def tx(el, *names):
    for n in names:
        for c in el:
            if c.tag.split("}")[-1] == n and (c.text or "").strip():
                return c.text.strip()
    return ""


def parse_feed(xml, f):
    root, z, out = ET.fromstring(xml), zone(f), []
    for n in root.iter():
        if n.tag.split("}")[-1] not in ("item", "entry"):
            continue
        link = ""
        for c in n:
            if c.tag.split("}")[-1] == "link":
                link = (c.get("href") or c.text or "").strip()
                if link and c.get("rel") in (None, "alternate"):
                    break
        link = link if re.match(r"https?://", link, re.I) else "#"
        title = plain(tx(n, "title")) or "(sans titre)"
        guid = tx(n, "guid", "id") or link
        cats = [(c.text or c.get("term") or "").strip() for c in n if c.tag.split("}")[-1] == "category"]
        rel = next((c.lower() for c in cats if c.lower() in ("confirmed", "credible")), "") if z == "leak" else ""
        out.append(dict(id=f"{f['id']}|{guid or title}", fid=f["id"], z=z, title=title, link=link,
                        sum=plain(tx(n, "encoded", "content", "description", "summary"), 200),
                        ts=ms(tx(n, "pubDate", "published", "updated", "date")), src=f["name"], lang=f["lang"],
                        cats=cats, rel=rel))
    return out[:60]


def build_feeds(meta):
    old = (prev("feeds.json") or {}).get("items", [])

    def one(f):
        try:
            items = parse_feed(get(f["url"]), f)
            if not items:
                raise ValueError("flux vide")
            return f, items, None
        except Exception as e:
            return f, [a for a in old if a["fid"] == f["id"]], str(e)[:160]  # on garde l'ancien contenu

    items = []
    with ThreadPoolExecutor(6) as ex:
        for f, it, err in ex.map(one, FEEDS):
            meta["feeds"][f["id"]] = dict(ok=err is None, n=len(it), err=err or "")
            items += it
    items.sort(key=lambda a: a["ts"], reverse=True)
    return dict(items=items[:500])


def build_kev():
    err = None
    for u in (KEV, KEVM):
        try:
            j = json.loads(get(u, timeout=90))
            break
        except Exception as e:
            err = e
    else:
        raise err
    KEV_IDS.update(x["cveID"] for x in j["vulnerabilities"])
    v = [dict(id=x["cveID"], v=x["vendorProject"], p=x["product"], n=x["vulnerabilityName"], d=x["dateAdded"],
              r=x.get("knownRansomwareCampaignUse") == "Known", due=x.get("dueDate", "")) for x in j["vulnerabilities"]]
    v.sort(key=lambda x: x["d"], reverse=True)
    return dict(via="serveur", total=j["count"], rel=j["dateReleased"], v=v[:80])


def compact(j, x):
    c = j.get("containers", {}).get("cna", {})
    sc, ex = 0, ""
    metrics = list(c.get("metrics") or []) + [m for a in j.get("containers", {}).get("adp", []) for m in a.get("metrics", [])]
    for m in metrics:
        for k in ("cvssV4_0", "cvssV3_1", "cvssV3_0"):
            b = (m.get(k) or {}).get("baseScore")
            if isinstance(b, (int, float)) and b > sc:
                sc = b
        o = m.get("other") or {}
        if o.get("type") == "ssvc":
            for q in (o.get("content") or {}).get("options", []):
                if q.get("Exploitation"):
                    ex = q["Exploitation"]
    a = (c.get("affected") or [{}])[0]
    t = c.get("title") or (c.get("descriptions") or [{}])[0].get("value", "")
    return dict(id=x["id"], ts=x["ts"], v=a.get("vendor", ""), p=a.get("product", ""), t=re.sub(r"\s+", " ", t)[:140], s=sc, e=ex)


def epss(ids):
    """{cve: (score, percentile)} ; les CVE trop récents n'ont pas encore de score."""
    ids = list(ids)

    def one(b):
        try:
            j = json.loads(get(EPSS + "?cve=" + ",".join(b), timeout=30))
            return {x["cve"]: (float(x["epss"]), float(x.get("percentile") or 0)) for x in j.get("data", [])}
        except Exception:
            return {}

    out = {}
    with ThreadPoolExecutor(4) as ex:
        for r in ex.map(one, [ids[i:i + 80] for i in range(0, len(ids), 80)]):
            out.update(r)
    return out


def build_cve():
    t = get(GH + "deltaLog.json", headers={"Range": "bytes=0-6000000"}, timeout=120).decode("utf-8", "ignore")
    log = json.loads(t[: t.rfind("\n  },")] + "\n  }]")
    m = {}
    for e in log:
        for n in e["new"]:
            m.setdefault(n["cveId"], dict(id=n["cveId"], ts=ms(n["dateUpdated"]), l=n["githubLink"]))
    arr = sorted(m.values(), key=lambda x: x["ts"], reverse=True)
    now = int(datetime.now(timezone.utc).timestamp() * 1000)
    day = 86400000
    cov = ms(log[-1]["fetchTime"])
    hours = [0] * 48
    for x in arr:
        h = (now - x["ts"]) // 3600000
        if 0 <= h < 48:
            hours[47 - h] += 1
    tz, jours = ZoneInfo("Europe/Paris"), ["lun.", "mar.", "mer.", "jeu.", "ven.", "sam.", "dim."]
    d0 = datetime.now(tz).replace(hour=0, minute=0, second=0, microsecond=0)
    days = []
    for k in range(6, -1, -1):
        a = d0 - timedelta(days=k)
        b = a + timedelta(days=1)
        if int(a.timestamp() * 1000) < cov:
            continue
        a_ms, b_ms = int(a.timestamp() * 1000), int(b.timestamp() * 1000)
        days.append([f"{jours[a.weekday()]} {a.day}", sum(1 for x in arr if a_ms <= x["ts"] < b_ms)])
    old = (prev("cve.json") or {}).get("recs", {})
    recent = [x for x in arr if now - x["ts"] < 3 * day]
    recs = {x["id"]: old[x["id"]] for x in recent if x["id"] in old}
    todo = [x for x in recent if x["id"] not in recs][:500]

    def fetch(x):
        try:
            return compact(json.loads(get(x["l"], timeout=30)), x)
        except Exception:
            return None

    with ThreadPoolExecutor(16) as ex:
        for r in ex.map(fetch, todo):
            if r:
                recs[r["id"]] = r
    kids = KEV_IDS or {x["id"] for x in (prev("kev.json") or {}).get("v", [])}
    sc = epss(recs)
    for i, r in recs.items():
        if i in sc:
            r["ep"], r["pc"] = round(sc[i][0], 4), round(sc[i][1], 3)
        if i in kids:
            r["k"] = True
        else:
            r.pop("k", None)
    gh = dict(at=now, since=cov, n24=sum(1 for x in arr if now - x["ts"] < day), n48=sum(1 for x in arr if now - x["ts"] < 2 * day),
              hours=hours, days=days, todo=len(todo), epss=len(sc))
    return dict(gh=gh, recs=recs)


def build_history():
    j = json.loads(get(HIST, timeout=120))
    return dict(at=j["generatedAt"], total=j["total"], days=j["days"][-90:], dc=j["dayCounts"][-90:],
                m=j["months"][-14:], mc=j["counts"][-14:], via="serveur")


RESOLVED = re.compile(r"resolved|restored|operating normally|completed|résolu", re.I)


def rss_events(xml):
    out = []
    for n in ET.fromstring(xml).iter():
        if n.tag.split("}")[-1] in ("item", "entry"):
            out.append(dict(t=plain(tx(n, "title")), d=plain(tx(n, "description", "summary", "content"), 160),
                            ts=ms(tx(n, "pubDate", "published", "updated"))))
    return out


def check_service(s):
    base = dict(id=s["id"], name=s["name"], url=s["url"])
    try:
        raw = get(s["feed"], timeout=25)
        if s["kind"] == "statuspage":
            j = json.loads(raw)
            st = j.get("status") or {}
            state = {"none": "ok", "minor": "deg", "major": "out", "critical": "out"}.get(st.get("indicator", ""), "unknown")
            inc = [i.get("name", "") for i in j.get("incidents", [])]
            return dict(base, state=state, note=(inc[0] if inc else st.get("description", ""))[:140], n=len(inc))
        ev = rss_events(raw)
        now = time.time() * 1000
        act = ev if s["kind"] == "rss_active" else [e for e in ev if e["ts"] and now - e["ts"] < 12 * 3600 * 1000 and not RESOLVED.search(e["t"] + " " + e["d"])]
        return dict(base, state="deg" if act else "ok", note=(act[0]["t"] if act else "Aucun incident en cours")[:140], n=len(act))
    except Exception as e:
        return dict(base, state="unknown", note=(s.get("hint") or "source indisponible : " + str(e))[:140], n=0)


STATE_CODE = {"ok": 0, "deg": 1, "out": 2, "unknown": 3}


def build_status():
    """Relevé courant + historique 7 jours par service : hist = [[horodatage ms, code 0 normal/1 dégradé/2 panne/3 inconnu], ...]"""
    old = {x["id"]: x.get("hist", []) for x in (prev("status.json") or {}).get("services", [])}
    with ThreadPoolExecutor(5) as ex:
        res = list(ex.map(check_service, STATUS))
    now = int(time.time() * 1000)
    for r in res:
        h = [x for x in old.get(r["id"], []) if now - x[0] < 7 * 86400000]
        if h and now - h[-1][0] < 300000:  # deux exécutions rapprochées : on remplace le dernier relevé
            h.pop()
        h.append([now, STATE_CODE.get(r["state"], 3)])
        r["hist"] = h[-400:]
    return dict(at=datetime.now(timezone.utc).isoformat(), services=res)


def build_ransom():
    old = (prev("ransom.json") or {}).get("items", [])
    items, errs, ok = {}, [], False
    for x in old:
        items[(x["v"].lower(), x["g"].lower(), x["d"] // 86400000)] = x
    for url, fr_only in RANSOM:
        try:
            j = json.loads(get(url, timeout=40))
            if isinstance(j, dict):
                j = j.get("victims") or j.get("data") or []
            ok = True
        except Exception as e:
            errs.append(f"{url.split('.live')[-1]} : {str(e)[:60]}")
            continue
        for x in j:
            if not isinstance(x, dict) or not (fr_only or str(x.get("country", "")).upper() == "FR"):
                continue
            v = str(x.get("victim") or x.get("post_title") or x.get("name") or "").strip()
            g = str(x.get("group") or x.get("group_name") or "").strip()
            d = ms(str(x.get("discovered") or x.get("published") or x.get("date") or x.get("attackdate") or "").replace(" ", "T", 1))
            if v and d:
                items[(v.lower(), g.lower(), d // 86400000)] = dict(v=v[:100], g=g[:40], d=d, a=str(x.get("activity") or x.get("sector") or "")[:40])
    if not ok:
        raise RuntimeError("; ".join(errs))
    lim = time.time() * 1000 - 60 * 86400000
    out = sorted((x for x in items.values() if x["d"] > lim), key=lambda x: x["d"], reverse=True)[:150]
    return dict(at=datetime.now(timezone.utc).isoformat(), items=out)


def main():
    os.makedirs(OUT, exist_ok=True)
    meta = dict(generatedAt=datetime.now(timezone.utc).isoformat(), feeds={}, parts={})
    jobs = [("feeds.json", lambda: build_feeds(meta)), ("kev.json", build_kev), ("cve.json", build_cve), ("history.json", build_history),
            ("status.json", build_status), ("ransom.json", build_ransom)]
    for name, fn in jobs:
        try:
            data = fn()
            meta["parts"][name] = "ok"
        except Exception as e:
            data = prev(name)  # on conserve la version précédente
            meta["parts"][name] = f"erreur : {str(e)[:150]}" + (" (ancienne version conservée)" if data else "")
        if data is not None:
            json.dump(data, open(os.path.join(OUT, name), "w", encoding="utf-8"), ensure_ascii=False, separators=(",", ":"))
    json.dump(meta, open(os.path.join(OUT, "meta.json"), "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print(json.dumps(meta["parts"], ensure_ascii=False, indent=1))


main()
