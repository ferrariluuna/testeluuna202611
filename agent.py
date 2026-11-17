"""Site Sentinel - agente automatizado de monitoramento com IA, relatórios e painel live.
Rodar:  uvicorn agent:app --host 0.0.0.0 --port 8000
"""
import asyncio, base64, datetime as dt, html, json, os, re, secrets, smtplib, socket, sqlite3, ssl, time
from collections import Counter
from contextlib import asynccontextmanager
from urllib.parse import urljoin, urlparse

import httpx, yaml
from fastapi import FastAPI, Request, Response
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

CFG = yaml.safe_load(open(os.getenv("CONFIG", "config.yaml"), encoding="utf-8"))
DATA = os.getenv("DATA_DIR", ".")
REPORT_DIR = os.path.join(DATA, "reports")
os.makedirs(REPORT_DIR, exist_ok=True)
db = sqlite3.connect(os.path.join(DATA, "sentinel.db"), check_same_thread=False)
# cada site com `browser: true` ganha uma checagem extra em navegador real (Playwright)
CFG["sites"] += [dict(x, name=x["name"] + " (navegador)", mode="browser", interval=x.get("browser_interval", 600))
                 for x in CFG["sites"] if x.get("browser")]
db.executescript("""
CREATE TABLE IF NOT EXISTS checks(id INTEGER PRIMARY KEY, ts REAL, site TEXT, state TEXT, status INT,
  total_ms REAL, ttfb_ms REAL, hops INT, final_url TEXT, ssl_days INT, error TEXT, issues TEXT);
CREATE TABLE IF NOT EXISTS incidents(id INTEGER PRIMARY KEY, site TEXT, started REAL, ended REAL,
  reason TEXT, diagnosis TEXT);
CREATE INDEX IF NOT EXISTS ix_checks ON checks(site, ts);
""")
subs: set = set()
state: dict = {}
_ssl_cache: dict = {}


# ---------- IA (opcional: defina ANTHROPIC_API_KEY) ----------
async def ai(prompt: str, max_tokens=700):
    if not os.getenv("ANTHROPIC_API_KEY"):
        return None
    try:
        import anthropic
        m = await anthropic.AsyncAnthropic().messages.create(
            model=os.getenv("AI_MODEL", "claude-sonnet-5-5"), max_tokens=max_tokens,
            messages=[{"role": "user", "content": prompt}])
        return m.content[0].text
    except Exception:
        return None


def _send_email(subject, body, html_body=None):
    host, to = os.getenv("SMTP_HOST"), os.getenv("EMAIL_TO")
    if not (host and to):
        return
    from email.message import EmailMessage
    m = EmailMessage()
    m["Subject"], m["To"] = subject, to
    m["From"] = os.getenv("EMAIL_FROM") or os.getenv("SMTP_USER") or "sentinel@localhost"
    m.set_content(body)
    if html_body:
        m.add_alternative(html_body, subtype="html")
    with smtplib.SMTP(host, int(os.getenv("SMTP_PORT", "587")), timeout=20) as srv:
        srv.starttls()
        if os.getenv("SMTP_USER"):
            srv.login(os.getenv("SMTP_USER"), os.getenv("SMTP_PASS", ""))
        srv.send_message(m)


async def notify(text: str, subject: str = None, html_body: str = None):
    """Envia para webhook (Slack/Discord) e/ou e-mail, conforme o que estiver configurado."""
    url = os.getenv("WEBHOOK_URL") or CFG.get("webhook_url")
    if url:
        try:
            async with httpx.AsyncClient(timeout=10) as c:
                await c.post(url, json={"text": text, "content": text})
        except Exception as e:
            print("webhook falhou:", e)
    try:
        await asyncio.to_thread(_send_email, subject or text.splitlines()[0][:90], text, html_body)
    except Exception as e:
        print("e-mail falhou:", e)


def publish(ev: dict):
    for q in list(subs):
        q.put_nowait(ev)


# ---------- Checagens ----------
def ssl_days(host: str):
    c = _ssl_cache.get(host)
    if c and time.time() - c[0] < 6 * 3600:
        return c[1]
    ctx = ssl.create_default_context()
    with socket.create_connection((host, 443), timeout=8) as s:
        with ctx.wrap_socket(s, server_hostname=host) as ss:
            exp = ssl.cert_time_to_seconds(ss.getpeercert()["notAfter"])
    d = int((exp - time.time()) // 86400)
    _ssl_cache[host] = (time.time(), d)
    return d


ERROR_PATTERNS = re.compile(
    r"Traceback \(most recent call last\)|Fatal error|Uncaught \w*Exception|Internal Server Error|"
    r"Application Error|SQLSTATE|Stack trace:|Unhandled Runtime Error|ChunkLoadError", re.I)


async def broken_links(client, base, body, limit=15):
    host, links = urlparse(base).netloc, []
    for h in re.findall(r'href=["\']([^"\'#]+)', body):
        u = urljoin(base, h)
        if u.startswith("http") and urlparse(u).netloc == host and u not in links:
            links.append(u)

    async def one(u):
        try:
            r = await client.head(u, follow_redirects=True)
            if r.status_code in (405, 501):
                r = await client.get(u, follow_redirects=True)
            return u, r.status_code
        except Exception:
            return u, 0
    res = await asyncio.gather(*(one(u) for u in links[:limit]))
    return [(u, c) for u, c in res if c == 0 or c >= 400]


async def probe(client: httpx.AsyncClient, site: dict) -> dict:
    cur, chain, issues, seen = site["url"], [], [], set()
    status = ttfb = None
    body, error, t0 = "", None, time.perf_counter()
    try:
        for _ in range(15):
            if cur in seen:
                issues.append(("critical", "redirect_loop", f"Loop de redirecionamento em {cur}"))
                break
            seen.add(cur)
            h0 = time.perf_counter()
            async with client.stream("GET", cur) as r:
                ttfb = (time.perf_counter() - h0) * 1000
                chain.append((cur, r.status_code))
                if r.is_redirect and "location" in r.headers:
                    nxt = urljoin(cur, r.headers["location"])
                    if cur.startswith("https") and nxt.startswith("http://"):
                        issues.append(("critical", "https_downgrade", f"Redireciona de HTTPS para HTTP: {nxt}"))
                    cur = nxt
                    continue
                status = r.status_code
                body = (await r.aread()).decode(r.encoding or "utf-8", "ignore")[:500_000]
                break
        else:
            issues.append(("critical", "too_many_redirects", "Redirecionamentos em excesso"))
    except httpx.TimeoutException:
        error = "Timeout"
    except Exception as e:
        error = f"{type(e).__name__}: {e}"[:200]
    total = (time.perf_counter() - t0) * 1000

    if error:
        issues.append(("critical", "unreachable", error))
    if status is not None and status >= 400:
        issues.append(("critical", f"http_{status}", f"Resposta HTTP {status}"))
    hops = max(len(chain) - 1, 0)
    if hops > site.get("max_redirects", 3):
        issues.append(("warning", "redirect_chain", f"Cadeia com {hops} redirecionamentos"))
    final = chain[-1][0] if chain else site["url"]
    if site.get("expect_final") and status and final.rstrip("/") != site["expect_final"].rstrip("/"):
        issues.append(("critical", "wrong_final_url", f"URL final {final} difere da esperada"))
    if status and status < 400:
        if total > site.get("slow_ms", 3000):
            issues.append(("warning", "slow", f"Carregamento lento: {total:.0f} ms"))
        if site.get("expect_text") and site["expect_text"] not in body:
            issues.append(("critical", "content_missing", f"Texto esperado ausente: {site['expect_text']!r}"))
        if ERROR_PATTERNS.search(body):
            issues.append(("warning", "error_leak", "Página 200 exibindo mensagem de erro/stack trace"))
        if final.startswith("https") and re.search(r'(?:src)=["\']http://', body):
            issues.append(("warning", "mixed_content", "Recursos HTTP em página HTTPS"))
        if site.get("check_links"):
            bad = await broken_links(client, final, body, site.get("links_limit", 15))
            if bad:
                issues.append(("warning", "broken_links", "Links quebrados: " + ", ".join(f"{u} ({c})" for u, c in bad[:5])))
    days = None
    if final.startswith("https"):
        try:
            days = await asyncio.to_thread(ssl_days, urlparse(final).hostname)
            if days < 7:
                issues.append(("critical", "ssl_expiring", f"Certificado expira em {days} dias"))
            elif days < 30:
                issues.append(("warning", "ssl_expiring", f"Certificado expira em {days} dias"))
        except Exception as e:
            issues.append(("critical", "ssl_error", f"Falha SSL: {e}"[:150]))
    st = "down" if any(i[0] == "critical" for i in issues) else "degraded" if issues else "up"
    return dict(site=site["name"], ts=time.time(), state=st, status=status, total_ms=round(total),
                ttfb_ms=round(ttfb) if ttfb else None, hops=hops, final_url=final, ssl_days=days,
                error=error, issues=[list(i) for i in issues])


_pw: dict = {}
_pw_lock = asyncio.Lock()
LCP_JS = """() => new Promise(res => { let lcp = null;
  try { new PerformanceObserver(l => { const e = l.getEntries(); lcp = e[e.length-1].startTime })
        .observe({type:'largest-contentful-paint', buffered:true}) } catch(e) {}
  setTimeout(() => { const n = performance.getEntriesByType('navigation')[0];
    res({lcp: lcp, ttfb: n ? n.responseStart : null, load: n ? n.loadEventEnd : null}) }, 1500) })"""


async def get_browser():
    async with _pw_lock:
        if "b" not in _pw or not _pw["b"].is_connected():
            from playwright.async_api import async_playwright
            _pw["p"] = _pw.get("p") or await async_playwright().start()
            _pw["b"] = await _pw["p"].chromium.launch(args=["--no-sandbox"])
        return _pw["b"]


async def browser_probe(client, site: dict) -> dict:
    """Abre a página num Chromium real: erros de JS, recursos 4xx/5xx e Core Web Vitals (LCP)."""
    t0, issues, js_errs, bad = time.perf_counter(), [], [], []
    status, final, m = None, site["url"], {}
    ignore = site.get("ignore_hosts", [])
    skip = lambda u: any(h in u for h in ignore)
    ctx = None
    try:
        browser = await get_browser()
        ctx = await browser.new_context(locale="pt-BR", viewport={"width": 1366, "height": 800})
        page = await ctx.new_page()
        page.on("pageerror", lambda e: js_errs.append(str(e)[:160]))
        page.on("console", lambda c: c.type == "error" and not c.text.startswith("Failed to load resource")
                and js_errs.append(c.text[:160]))
        page.on("response", lambda r: r.status >= 400 and not skip(r.url) and bad.append((r.url, r.status)))
        page.on("requestfailed", lambda r: not skip(r.url) and "ERR_ABORTED" not in str(r.failure)
                and bad.append((r.url, 0)))
        resp = await page.goto(site["url"], wait_until="load", timeout=int(CFG.get("timeout", 15) * 2000))
        status, final = (resp.status if resp else None), page.url
        m = await page.evaluate(LCP_JS)
    except ImportError:
        issues.append(("warning", "playwright_missing", "Playwright não instalado; checagem em navegador desativada"))
    except Exception as e:
        issues.append(("critical", "browser_error", f"{type(e).__name__}: {e}"[:200]))
    finally:
        if ctx:
            await ctx.close()
    if status and status >= 400:
        issues.append(("critical", f"http_{status}", f"Resposta HTTP {status}"))
    if js_errs:
        issues.append(("warning", "js_errors", f"{len(js_errs)} erro(s) de JavaScript. Ex.: {js_errs[0]}"))
    if bad:
        issues.append(("warning", "resource_errors", f"{len(bad)} recurso(s) falharam: "
                       + ", ".join(f"{u[:70]} ({c})" for u, c in bad[:3])))
    if m.get("lcp") and m["lcp"] > site.get("lcp_ms", 4000):
        issues.append(("warning", "slow_lcp", f"LCP alto: {m['lcp']:.0f} ms (ideal < 2500)"))
    total = m.get("load") or (time.perf_counter() - t0) * 1000
    st = "down" if any(i[0] == "critical" for i in issues) else "degraded" if issues else "up"
    return dict(site=site["name"], ts=time.time(), state=st, status=status, total_ms=round(total),
                ttfb_ms=round(m["ttfb"]) if m.get("ttfb") else None, hops=0, final_url=final,
                ssl_days=None, error=None, issues=[list(i) for i in issues])


async def handle(res: dict):
    db.execute("INSERT INTO checks(ts,site,state,status,total_ms,ttfb_ms,hops,final_url,ssl_days,error,issues)"
               " VALUES(?,?,?,?,?,?,?,?,?,?,?)",
               (res["ts"], res["site"], res["state"], res["status"], res["total_ms"], res["ttfb_ms"], res["hops"],
                res["final_url"], res["ssl_days"], res["error"], json.dumps(res["issues"], ensure_ascii=False)))
    db.commit()
    s = state.setdefault(res["site"], {"fails": 0, "inc": None})
    if res["state"] == "down":
        s["fails"] += 1
        if s["fails"] >= CFG.get("confirm_failures", 2) and s["inc"] is None:
            reason = "; ".join(i[2] for i in res["issues"] if i[0] == "critical")
            diag = await ai(f"Você é um SRE. O site {res['site']} caiu. Problemas detectados: {reason}. "
                            f"Cadeia/URL final: {res['final_url']}. Dê em português, em até 5 linhas, "
                            "causas prováveis e o que checar primeiro.")
            cur = db.execute("INSERT INTO incidents(site,started,reason,diagnosis) VALUES(?,?,?,?)",
                             (res["site"], res["ts"], reason, diag))
            db.commit()
            s["inc"] = cur.lastrowid
            await notify(f"🔴 {res['site']} FORA DO AR: {reason}" + (f"\n\nDiagnóstico IA:\n{diag}" if diag else ""))
            publish({"type": "incident"})
    else:
        s["fails"] = 0
        if s["inc"]:
            db.execute("UPDATE incidents SET ended=? WHERE id=?", (res["ts"], s["inc"]))
            db.commit()
            s["inc"] = None
            await notify(f"🟢 {res['site']} voltou ao normal.")
            publish({"type": "incident"})
    publish({"type": "check", "site": res["site"]})


async def site_loop(client, site):
    while True:
        try:
            fn = browser_probe if site.get("mode") == "browser" else probe
            await handle(await fn(client, site))
        except Exception as e:
            print("erro no loop", site["name"], e)
        await asyncio.sleep(site.get("interval", CFG.get("interval", 60)))


# ---------- Estatísticas e relatórios ----------
def stats(hours: float):
    since, out = time.time() - hours * 3600, []
    for s in CFG["sites"]:
        rows = db.execute("SELECT state,total_ms,issues FROM checks WHERE site=? AND ts>?", (s["name"], since)).fetchall()
        n = len(rows)
        lat = sorted(r[1] for r in rows if r[1] is not None)
        codes = Counter(i[1] for r in rows for i in json.loads(r[2] or "[]"))
        out.append(dict(site=s["name"], url=s["url"], checks=n,
                        uptime=round(100 * sum(r[0] != "down" for r in rows) / n, 2) if n else None,
                        avg_ms=round(sum(lat) / len(lat)) if lat else None,
                        p95_ms=lat[int(len(lat) * 0.95) - 1 if len(lat) > 1 else 0] if lat else None,
                        issues=dict(codes.most_common(6))))
    return out


def incidents(limit=30, since=0):
    cols = ("id", "site", "started", "ended", "reason", "diagnosis")
    rows = db.execute("SELECT * FROM incidents WHERE started>? ORDER BY id DESC LIMIT ?", (since, limit)).fetchall()
    return [dict(zip(cols, r)) for r in rows]


async def make_report(hours=24) -> str:
    st, inc = stats(hours), incidents(100, time.time() - hours * 3600)
    summary = await ai("Escreva em português um resumo executivo (máx. 200 palavras) deste relatório de monitoramento "
                       f"das últimas {hours}h, com principais problemas, causas prováveis e ações recomendadas, "
                       f"em texto corrido. Dados: {json.dumps(st, ensure_ascii=False)} "
                       f"Incidentes: {json.dumps(inc, ensure_ascii=False)}", 900)
    fmt = lambda t: dt.datetime.fromtimestamp(t).strftime("%d/%m %H:%M") if t else "em andamento"
    rows = "".join(f"<tr><td>{html.escape(s['site'])}</td><td>{s['uptime']}%</td><td>{s['avg_ms']} ms</td>"
                   f"<td>{s['p95_ms']} ms</td><td>{html.escape(', '.join(f'{k}×{v}' for k, v in s['issues'].items()) or '—')}</td></tr>"
                   for s in st)
    irows = "".join(f"<tr><td>{html.escape(i['site'])}</td><td>{fmt(i['started'])}</td><td>{fmt(i['ended'])}</td>"
                    f"<td>{html.escape(i['reason'] or '')}</td></tr>" for i in inc) or "<tr><td colspan=4>Nenhum incidente 🎉</td></tr>"
    now = dt.datetime.now()
    doc = f"""<!doctype html><meta charset=utf-8><title>Relatório de monitoramento</title>
<style>body{{font:15px system-ui;max-width:900px;margin:2rem auto;padding:0 1rem;color:#1a1a1a}}
table{{border-collapse:collapse;width:100%;margin:1rem 0}}td,th{{border-bottom:1px solid #ddd;padding:.5rem;text-align:left}}
.ai{{background:#f3f0ff;padding:1rem;border-radius:8px;white-space:pre-wrap}}</style>
<h1>Relatório de monitoramento</h1><p>Últimas {hours}h · gerado em {now:%d/%m/%Y %H:%M}</p>
{f'<h2>Análise da IA</h2><div class=ai>{html.escape(summary)}</div>' if summary else ''}
<h2>Disponibilidade e performance</h2><table><tr><th>Site<th>Uptime<th>Média<th>P95<th>Problemas</tr>{rows}</table>
<h2>Incidentes</h2><table><tr><th>Site<th>Início<th>Fim<th>Motivo</tr>{irows}</table>"""
    name = f"relatorio-{now:%Y%m%d-%H%M}.html"
    open(os.path.join(REPORT_DIR, name), "w", encoding="utf-8").write(doc)
    await notify(f"📊 Relatório pronto: {name}", f"Relatório de monitoramento {now:%d/%m/%Y}", doc)
    publish({"type": "report"})
    return name


async def report_loop():
    hh, mm = map(int, CFG.get("report_time", "08:00").split(":"))
    while True:
        now = dt.datetime.now()
        nxt = now.replace(hour=hh, minute=mm, second=0, microsecond=0)
        if nxt <= now:
            nxt += dt.timedelta(days=1)
        await asyncio.sleep((nxt - now).total_seconds())
        await make_report(24)


# ---------- API + painel ----------
@asynccontextmanager
async def lifespan(app):
    client = httpx.AsyncClient(timeout=CFG.get("timeout", 15), follow_redirects=False,
                               headers={"User-Agent": "SiteSentinel/1.0"})
    tasks = [asyncio.create_task(site_loop(client, s)) for s in CFG["sites"]] + [asyncio.create_task(report_loop())]
    yield
    for t in tasks:
        t.cancel()
    await client.aclose()


app = FastAPI(lifespan=lifespan)
app.mount("/reports", StaticFiles(directory=REPORT_DIR), name="reports")


@app.middleware("http")
async def basic_auth(request: Request, call_next):
    """Protege painel, API, SSE e relatórios quando DASH_USER e DASH_PASS estão definidos."""
    u, p = os.getenv("DASH_USER"), os.getenv("DASH_PASS")
    if u and p:
        ok, h = False, request.headers.get("authorization", "")
        if h.startswith("Basic "):
            try:
                cu, _, cp = base64.b64decode(h[6:]).decode().partition(":")
                ok = secrets.compare_digest(cu.encode(), u.encode()) and secrets.compare_digest(cp.encode(), p.encode())
            except Exception:
                pass
        if not ok:
            return Response(status_code=401, headers={"WWW-Authenticate": 'Basic realm="Site Sentinel"'})
    return await call_next(request)


@app.get("/api/status")
def api_status():
    up = {s["site"]: s["uptime"] for s in stats(24)}
    out = []
    for s in CFG["sites"]:
        r = db.execute("SELECT ts,state,status,total_ms,ttfb_ms,hops,ssl_days,error,issues FROM checks "
                       "WHERE site=? ORDER BY id DESC LIMIT 1", (s["name"],)).fetchone()
        spark = [x[0] for x in db.execute("SELECT total_ms FROM checks WHERE site=? ORDER BY id DESC LIMIT 40", (s["name"],))][::-1]
        d = dict(name=s["name"], url=s["url"], uptime=up[s["name"]], spark=spark)
        if r:
            d.update(zip(("ts", "state", "status", "total_ms", "ttfb_ms", "hops", "ssl_days", "error"), r[:8]))
            d["issues"] = json.loads(r[8] or "[]")
        out.append(d)
    return out


@app.get("/api/incidents")
def api_incidents():
    return incidents()


@app.get("/api/reports")
def api_reports():
    return sorted(os.listdir(REPORT_DIR), reverse=True)[:15]


@app.post("/api/report")
async def api_report(hours: int = 24):
    return {"file": await make_report(hours)}


@app.get("/events")
async def events():
    q = asyncio.Queue()
    subs.add(q)

    async def gen():
        try:
            while True:
                try:
                    yield f"data: {json.dumps(await asyncio.wait_for(q.get(), 20))}\n\n"
                except asyncio.TimeoutError:
                    yield ": ping\n\n"
        finally:
            subs.discard(q)
    return StreamingResponse(gen(), media_type="text/event-stream")


@app.get("/", response_class=HTMLResponse)
def index():
    return PAGE


PAGE = """<!doctype html><html lang="pt-BR"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Site Sentinel</title>
<style>
:root{--bg:#f6f7f9;--card:#fff;--tx:#16181d;--mut:#6b7280;--bd:#e5e7eb;--up:#16a34a;--deg:#d97706;--down:#dc2626}
@media(prefers-color-scheme:dark){:root{--bg:#0f1115;--card:#171a21;--tx:#e8eaee;--mut:#8b93a1;--bd:#262b35}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--tx);font:14px system-ui,sans-serif;padding:1.2rem}
header{display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:.6rem;margin-bottom:1rem}
h1{font-size:1.2rem;margin:0}.live{color:var(--up);font-size:.8rem}
button{background:var(--tx);color:var(--bg);border:0;border-radius:6px;padding:.5rem .9rem;cursor:pointer}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:.9rem}
.card{background:var(--card);border:1px solid var(--bd);border-radius:10px;padding:1rem;border-top:3px solid var(--c)}
.card.up{--c:var(--up)}.card.degraded{--c:var(--deg)}.card.down{--c:var(--down)}
.row{display:flex;justify-content:space-between;align-items:center}.pill{color:var(--c);font-weight:600;text-transform:uppercase;font-size:.72rem}
.url{color:var(--mut);font-size:.78rem;word-break:break-all}.m{display:grid;grid-template-columns:repeat(4,1fr);gap:.4rem;margin:.8rem 0}
.m b{display:block;font-size:1rem}.m span{color:var(--mut);font-size:.7rem}svg{width:100%;height:34px;color:var(--c)}
.iss{color:var(--deg);font-size:.78rem;margin:.2rem 0}.iss.critical{color:var(--down)}
section{margin-top:1.4rem}table{width:100%;border-collapse:collapse;background:var(--card);border-radius:10px;overflow:hidden}
td,th{padding:.55rem .7rem;border-bottom:1px solid var(--bd);text-align:left;font-size:.82rem}a{color:inherit}
</style></head><body>
<header><h1>🛰️ Site Sentinel <span class="live" id="live">● ao vivo</span></h1>
<button onclick="gen()">Gerar relatório agora</button></header>
<div class="grid" id="grid"></div>
<section><h3>Incidentes</h3><table id="inc"></table></section>
<section><h3>Relatórios</h3><div id="rep"></div></section>
<script>
const $=s=>document.querySelector(s),esc=s=>String(s??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const spark=v=>{if(v.length<2)return'';const mx=Math.max(...v,1);
return`<svg viewBox="0 0 100 30" preserveAspectRatio="none"><polyline fill="none" stroke="currentColor" stroke-width="1.6" vector-effect="non-scaling-stroke" points="${v.map((y,i)=>(i/(v.length-1)*100).toFixed(1)+','+(29-(y||0)/mx*27).toFixed(1)).join(' ')}"/></svg>`};
const t=ts=>ts?new Date(ts*1000).toLocaleString('pt-BR',{dateStyle:'short',timeStyle:'short'}):'em andamento';
async function load(){
 const s=await (await fetch('/api/status')).json();
 $('#grid').innerHTML=s.map(x=>`<div class="card ${x.state||''}"><div class="row"><b>${esc(x.name)}</b><span class="pill">${x.state||'aguardando'}</span></div>
 <div class="url">${esc(x.url)}</div><div class="m"><div><b>${x.status??'—'}</b><span>HTTP</span></div><div><b>${x.total_ms??'—'}ms</b><span>carga</span></div>
 <div><b>${x.ttfb_ms??'—'}ms</b><span>TTFB</span></div><div><b>${x.uptime??'—'}%</b><span>uptime 24h</span></div></div>
 ${spark(x.spark||[])}<div class="url">redirects: ${x.hops??0} · SSL: ${x.ssl_days??'—'} dias</div>
 ${(x.issues||[]).map(i=>`<div class="iss ${i[0]}">⚠ ${esc(i[2])}</div>`).join('')}</div>`).join('');
 const i=await (await fetch('/api/incidents')).json();
 $('#inc').innerHTML='<tr><th>Site<th>Início<th>Fim<th>Motivo<th>Diagnóstico IA</tr>'+(i.map(r=>`<tr><td>${esc(r.site)}<td>${t(r.started)}<td>${t(r.ended)}<td>${esc(r.reason)}<td>${esc(r.diagnosis||'—')}</tr>`).join('')||'<tr><td colspan=5>Nenhum incidente</tr>');
 const r=await (await fetch('/api/reports')).json();
 $('#rep').innerHTML=r.map(f=>`<div><a href="/reports/${f}" target="_blank">${f}</a></div>`).join('')||'Nenhum ainda';
}
async function gen(){await fetch('/api/report',{method:'POST'});load()}
load();const es=new EventSource('/events');es.onmessage=load;
es.onerror=()=>$('#live').textContent='○ reconectando…';es.onopen=()=>$('#live').textContent='● ao vivo';
</script></body></html>"""
