"""Site Sentinel (modo GitHub Actions): faz UMA rodada de checagens por execução.
Reaproveita as checagens do agent.py e grava histórico, incidentes e relatórios em docs/data/."""
import argparse, asyncio, datetime as dt, glob, gzip, html, json, os, re, time
from collections import Counter
from urllib.parse import urljoin, urlparse
from zoneinfo import ZoneInfo

os.environ.setdefault("DATA_DIR", "/tmp/sentinel")
import httpx
import agent
from agent import CFG, ai, notify

OUT = "docs/data"
TZ = ZoneInfo(CFG.get("timezone", "America/Sao_Paulo"))
CONFIRM = CFG.get("confirm_failures_actions", 1)
_o = os.getenv("GITHUB_REPOSITORY", "/").split("/")
DASH = f"https://{_o[0]}.github.io/{_o[1]}/" if len(_o) == 2 and _o[0] else ""
os.makedirs(f"{OUT}/reports", exist_ok=True)


def load(name, default):
    try:
        return json.load(open(f"{OUT}/{name}.json", encoding="utf-8"))
    except Exception:
        return default


def save(name, obj):
    json.dump(obj, open(f"{OUT}/{name}.json", "w", encoding="utf-8"), ensure_ascii=False, separators=(",", ":"))


def build_status(history):
    out, cut = [], time.time() - 86400
    for s in CFG["sites"]:
        rows = [h for h in history if h["site"] == s["name"]]
        if not rows:
            out.append({"name": s["name"], "url": s["url"], "state": None})
            continue
        last, r24 = rows[-1], [h for h in rows if h["ts"] > cut]
        out.append({"name": s["name"], "url": s["url"], "state": last["state"], "status": last["status"],
                    "total_ms": last["ms"], "ttfb_ms": last["ttfb"], "hops": last["hops"], "ssl_days": last["ssl"],
                    "issues": last["issues"], "ts": last["ts"],
                    "uptime": round(100 * sum(h["state"] != "down" for h in r24) / len(r24), 2) if r24 else None,
                    "spark": [h["ms"] for h in rows[-40:]], "browser": s.get("mode") == "browser"})
    return {"generated": int(time.time()), "sites": out}


# ---------- Catálogo de páginas (sitemap + Search Console) ----------
CAT = CFG.get("catalog", {})
CRIT = {"http_404", "http_5xx", "timeout", "unreachable", "noindex", "redirect_loop", "https_downgrade"}
META_ROBOTS = re.compile(r'''<meta[^>]+name=["']robots["'][^>]*>''', re.I)
CANON = re.compile(r'''<link[^>]+rel=["']canonical["'][^>]*>''', re.I)
HREF = re.compile(r'''href=["']([^"']+)["']''', re.I)
TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)


def site_root():
    u = urlparse(CFG["sites"][0]["url"])
    return f"{u.scheme}://{u.netloc}"


def read_local():
    """Lê URLs de CSVs exportados do Search Console (pasta gsc/) e de urls.txt."""
    d, urls = CAT.get("gsc_dir", "gsc"), set()
    for f in glob.glob(f"{d}/*.xlsx"):
        print("ignorado (exporte como CSV):", f)
    for f in glob.glob(f"{d}/*.csv") + glob.glob(f"{d}/*.txt") + [CAT.get("urls_file", "urls.txt")]:
        try:
            txt = open(f, encoding="utf-8-sig", errors="ignore").read()
        except OSError:
            continue
        urls.update(re.findall(r'''https?://[^\s,;"'<>]+''', txt))
    return urls


async def discover(client):
    root, maps, found, seen = site_root(), list(CAT.get("sitemaps") or []), set(), set()
    if not maps:
        try:
            r = await client.get(root + "/robots.txt", follow_redirects=True)
            maps = [l.split(":", 1)[1].strip() for l in r.text.splitlines() if l.lower().startswith("sitemap:")]
        except Exception:
            pass
        maps = maps or [root + "/sitemap.xml"]
    while maps and len(seen) < 60:
        sm = maps.pop(0)
        if sm in seen:
            continue
        seen.add(sm)
        try:
            r = await client.get(sm, follow_redirects=True)
            data = gzip.decompress(r.content) if r.content[:2] == b"\x1f\x8b" else r.content
            txt = data.decode("utf-8", "ignore")
        except Exception as e:
            print("sitemap falhou:", sm, e)
            continue
        locs = [html.unescape(x) for x in re.findall(r"<loc>\s*(.*?)\s*</loc>", txt, re.S)]
        if "<sitemapindex" in txt:
            maps.extend(locs)
        else:
            found.update(locs)
    dom = urlparse(root).netloc.removeprefix("www.")
    urls = {u.split("#")[0] for u in found | read_local()}
    urls = {u for u in urls if urlparse(u).netloc.removeprefix("www.") == dom
            and not any(x in u for x in CAT.get("exclude", []))}
    return sorted(urls)[:CAT.get("max_urls", 5000)]


async def check_page(client, url):
    t0, issues, cur, seen, hops = time.perf_counter(), [], url, set(), 0
    status, body, xrobots = None, "", ""
    try:
        for _ in range(8):
            if cur in seen:
                issues.append("redirect_loop")
                break
            seen.add(cur)
            async with client.stream("GET", cur) as r:
                if r.is_redirect and "location" in r.headers:
                    cur = urljoin(cur, r.headers["location"])
                    hops += 1
                    continue
                status, xrobots = r.status_code, r.headers.get("x-robots-tag", "")
                if status < 400 and "html" in r.headers.get("content-type", ""):
                    buf = b""
                    async for ch in r.aiter_bytes():
                        buf += ch
                        if len(buf) > 150_000:
                            break
                    body = buf.decode(r.encoding or "utf-8", "ignore")
            break
        else:
            issues.append("redirect_loop")
    except httpx.TimeoutException:
        issues.append("timeout")
    except Exception:
        issues.append("unreachable")
    ms = round((time.perf_counter() - t0) * 1000)
    if status is not None:
        if status in (404, 410):
            issues.append("http_404")
        elif status >= 500:
            issues.append("http_5xx")
        elif status >= 400:
            issues.append("http_4xx")
    if hops:
        issues.append("redirect")
    if hops > 2:
        issues.append("redirect_chain")
    if url.startswith("https") and cur.startswith("http://"):
        issues.append("https_downgrade")
    if status and status < 400 and ms > CAT.get("slow_ms", 3000):
        issues.append("slow")
    if body:
        m = META_ROBOTS.search(body)
        if (m and "noindex" in m.group(0).lower()) or "noindex" in xrobots.lower():
            issues.append("noindex")
        t = TITLE.search(body)
        if not (t and t.group(1).strip()):
            issues.append("no_title")
        c = CANON.search(body)
        h = HREF.search(c.group(0)) if c else None
        if h and urljoin(cur, h.group(1)).split("#")[0].split("?")[0].rstrip("/") != cur.split("#")[0].split("?")[0].rstrip("/"):
            issues.append("canonical_diff")
        if agent.ERROR_PATTERNS.search(body):
            issues.append("error_leak")
    elif "noindex" in xrobots.lower():
        issues.append("noindex")
    state = "problem" if any(i in CRIT for i in issues) else "warning" if issues else "ok"
    return {"ts": int(time.time()), "state": state, "status": status, "ms": ms, "hops": hops, "issues": issues,
            "final": cur if cur != url else None}


async def run_catalog(st):
    """Checa um lote rotativo do catálogo por rodada e grava o resumo para o painel."""
    cat = load("catalog", {"urls": {}, "cursor": 0})
    day = dt.datetime.now(TZ).strftime("%Y-%m-%d")
    async with httpx.AsyncClient(timeout=CFG.get("timeout", 15), follow_redirects=False,
                                 headers={"User-Agent": "SiteSentinel/1.0"}) as client:
        if cat.get("discovered") != day or not cat["urls"]:
            urls = await discover(client)
            if urls:
                cat["urls"] = {u: cat["urls"].get(u) for u in urls}
                cat["discovered"] = day
        keys = sorted(cat["urls"])
        if not keys:
            print("catálogo vazio: nenhum sitemap encontrado e nenhuma URL em gsc/ ou urls.txt")
            return None
        n = min(CAT.get("per_run", 60), len(keys))
        c = cat.get("cursor", 0) % len(keys)
        batch = (keys + keys)[c:c + n]
        batch += [u for u in keys if (cat["urls"][u] or {}).get("state") == "problem" and u not in batch][:20]
        cat["cursor"] = (c + n) % len(keys)
        sem = asyncio.Semaphore(8)

        async def one(u):
            async with sem:
                return u, await check_page(client, u)
        res = await asyncio.gather(*(one(u) for u in batch))
    # se quase tudo for 403/429, o site está bloqueando o robô: não grava nem alerta
    blocked = len(res) >= 10 and sum(e["status"] in (403, 429) for _, e in res) / len(res) >= 0.7
    cat["blocked"] = blocked
    if not blocked:
        newp = []
        for u, e in res:
            prev = (cat["urls"].get(u) or {}).get("state")
            cat["urls"][u] = e
            if e["state"] == "problem" and prev != "problem":
                newp.append((u, e))
        if newp:
            lines = "\n".join(f"• {u} → {', '.join(e['issues'])}" for u, e in newp[:10])
            await notify(f"⚠️ {len(newp)} página(s) do catálogo com problema novo:\n{lines}"
                         + (f"\n\nPainel: {DASH}" if DASH else ""))
    ents = [(u, e) for u, e in cat["urls"].items() if e]
    probs = [(u, e) for u, e in ents if e["state"] == "problem"]
    warns = [(u, e) for u, e in ents if e["state"] == "warning"]
    summ = {"updated": int(time.time()), "total": len(keys), "checked": len(ents), "with_problems": len(probs),
            "with_warnings": len(warns), "blocked": blocked,
            "by_issue": dict(Counter(i for _, e in ents for i in e["issues"]).most_common()),
            "problems": [{"url": u, "state": e["state"], "issues": e["issues"], "status": e["status"], "ts": e["ts"]}
                         for u, e in (probs + warns)[:100]]}
    save("catalog", cat)
    save("catalog_summary", summ)
    return summ


async def make_report(history, incs, local, csum=None):
    since, stats = time.time() - 86400, []
    for s in CFG["sites"]:
        r = [h for h in history if h["site"] == s["name"] and h["ts"] > since]
        lat = sorted(h["ms"] for h in r if h["ms"])
        stats.append(dict(site=s["name"], checks=len(r),
                          uptime=round(100 * sum(h["state"] != "down" for h in r) / len(r), 2) if r else None,
                          avg_ms=round(sum(lat) / len(lat)) if lat else None,
                          p95_ms=lat[max(0, int(len(lat) * 0.95) - 1)] if lat else None,
                          issues=dict(Counter(i[1] for h in r for i in h["issues"]).most_common(6))))
    recent = [i for i in incs if i["started"] > since]
    summary = await ai("Escreva em português um resumo executivo (máx. 200 palavras) deste relatório de monitoramento "
                       "das últimas 24h, com principais problemas, causas prováveis e ações recomendadas, em texto "
                       f"corrido. Dados: {json.dumps(stats, ensure_ascii=False)} "
                       f"Incidentes: {json.dumps(recent, ensure_ascii=False)} Catálogo SEO: {json.dumps((csum or {}).get('by_issue', {}), ensure_ascii=False)}", 900)
    fmt = lambda t: dt.datetime.fromtimestamp(t, TZ).strftime("%d/%m %H:%M") if t else "em andamento"
    rows = "".join(f"<tr><td>{html.escape(s['site'])}<td>{s['uptime']}%<td>{s['avg_ms']} ms<td>{s['p95_ms']} ms"
                   f"<td>{html.escape(', '.join(f'{k}×{v}' for k, v in s['issues'].items()) or '—')}</tr>" for s in stats)
    irows = "".join(f"<tr><td>{html.escape(i['site'])}<td>{fmt(i['started'])}<td>{fmt(i['ended'])}"
                    f"<td>{html.escape(i['reason'] or '')}</tr>" for i in recent) or "<tr><td colspan=4>Nenhum incidente 🎉</tr>"
    cat_html = ""
    if csum and csum.get("total"):
        prow = "".join(f"<tr><td>{html.escape(p['url'])}<td>{html.escape(', '.join(p['issues']))}<td>{p['status'] or '—'}</tr>"
                       for p in csum["problems"][:15]) or "<tr><td colspan=3>Nenhum problema 🎉</tr>"
        cat_html = (f"<h2>Catálogo de páginas (SEO)</h2><p>{csum['total']} URLs · {csum['checked']} checadas · "
                    f"{csum['with_problems']} com problema · {csum['with_warnings']} com aviso</p>"
                    f"<table><tr><th>URL<th>Problemas<th>HTTP</tr>{prow}</table>")
    doc = f"""<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>Relatório de monitoramento</title>
<style>body{{font:15px system-ui;max-width:900px;margin:2rem auto;padding:0 1rem;color:#1a1a1a}}
table{{border-collapse:collapse;width:100%;margin:1rem 0}}td,th{{border-bottom:1px solid #ddd;padding:.5rem;text-align:left}}
.ai{{background:#f3f0ff;padding:1rem;border-radius:8px;white-space:pre-wrap}}</style>
<h1>Relatório de monitoramento · Luuna</h1><p>Últimas 24h · gerado em {local:%d/%m/%Y %H:%M}</p>
{f'<h2>Análise da IA</h2><div class=ai>{html.escape(summary)}</div>' if summary else ''}
<h2>Disponibilidade e performance</h2><table><tr><th>Página<th>Uptime<th>Média<th>P95<th>Problemas</tr>{rows}</table>
<h2>Incidentes</h2><table><tr><th>Página<th>Início<th>Fim<th>Motivo</tr>{irows}</table>{cat_html}"""
    name = f"relatorio-{local:%Y%m%d}.html"
    open(f"{OUT}/reports/{name}", "w", encoding="utf-8").write(doc)
    reps = [name] + [r for r in load("reports", []) if r != name]
    save("reports", reps[:60])
    await notify(f"📊 Relatório diário pronto: {DASH}data/reports/{name}", f"Relatório de monitoramento {local:%d/%m/%Y}", doc)


async def main(mode: str):
    history, daily, incs, st = load("history", []), load("daily", {}), load("incidents", []), load("state", {})
    sites = [s for s in CFG["sites"] if (s.get("mode") == "browser") == (mode == "browser")]
    async with httpx.AsyncClient(timeout=CFG.get("timeout", 15), follow_redirects=False,
                                 headers={"User-Agent": "SiteSentinel/1.0"}) as client:
        fn = agent.browser_probe if mode == "browser" else agent.probe

        async def run(s):
            r = await fn(client, s)
            if r["state"] == "down" and mode != "browser":   # reconfere antes de alarmar
                await asyncio.sleep(15)
                r = await fn(client, s)
            return r
        results = await asyncio.gather(*(run(s) for s in sites))

    now, local = time.time(), dt.datetime.now(TZ)
    day = local.strftime("%Y-%m-%d")
    for r in results:
        history.append({"ts": int(r["ts"]), "site": r["site"], "state": r["state"], "status": r["status"],
                        "ms": r["total_ms"], "ttfb": r["ttfb_ms"], "hops": r["hops"], "ssl": r["ssl_days"],
                        "issues": r["issues"]})
        d = daily.setdefault(day, {}).setdefault(r["site"], {"n": 0, "ok": 0, "sum": 0, "cnt": 0, "max": 0, "issues": {}})
        d["n"] += 1
        d["ok"] += r["state"] != "down"
        if r["total_ms"] and r["status"]:
            d["sum"] += r["total_ms"]; d["cnt"] += 1; d["max"] = max(d["max"], r["total_ms"])
        for i in r["issues"]:
            d["issues"][i[1]] = d["issues"].get(i[1], 0) + 1

        s = st.setdefault(r["site"], {"fails": 0, "inc": None})
        if r["state"] == "down":
            s["fails"] += 1
            if s["fails"] >= CONFIRM and s["inc"] is None:
                reason = "; ".join(i[2] for i in r["issues"] if i[0] == "critical")
                diag = await ai(f"Você é um SRE. A página {r['site']} ({r['final_url']}) apresentou falha. Problemas: "
                                f"{reason}. Em português, em até 5 linhas, cite causas prováveis e o que checar primeiro.")
                inc = {"id": int(now * 1000), "site": r["site"], "started": int(now), "ended": None,
                       "reason": reason, "diagnosis": diag}
                incs.insert(0, inc)
                s["inc"] = inc["id"]
                await notify(f"🔴 {r['site']} COM PROBLEMA: {reason}" + (f"\n\nDiagnóstico IA:\n{diag}" if diag else "")
                             + (f"\n\nPainel: {DASH}" if DASH else ""))
        else:
            s["fails"] = 0
            if s["inc"]:
                for i in incs:
                    if i["id"] == s["inc"]:
                        i["ended"] = int(now)
                s["inc"] = None
                await notify(f"🟢 {r['site']} voltou ao normal.")

    csum = None
    if mode != "browser" and CAT.get("enabled"):
        try:
            csum = await run_catalog(st)
        except Exception as e:
            print("catálogo falhou:", e)
    cut = now - 48 * 3600
    history = [h for h in history if h["ts"] > cut]
    daily = {k: daily[k] for k in sorted(daily)[-120:]}
    if mode != "browser" and (local.hour, local.minute) >= tuple(map(int, CFG.get("report_time", "08:00").split(":"))) \
            and st.get("_last_report") != day:
        st["_last_report"] = day
        await make_report(history, incs, local, csum or load("catalog_summary", None))
    save("history", history); save("daily", daily); save("incidents", incs[:300]); save("state", st)
    save("status", build_status(history))
    print(f"ok: {len(results)} checagens ({mode}), {sum(r['state'] == 'down' for r in results)} com problema")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["http", "browser"], default="http")
    asyncio.run(main(ap.parse_args().mode))
