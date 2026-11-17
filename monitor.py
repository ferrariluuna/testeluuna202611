"""Site Sentinel (modo GitHub Actions): faz UMA rodada de checagens por execução.
Reaproveita as checagens do agent.py e grava histórico, incidentes e relatórios em docs/data/."""
import argparse, asyncio, datetime as dt, html, json, os, time
from collections import Counter
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


async def make_report(history, incs, local):
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
                       f"Incidentes: {json.dumps(recent, ensure_ascii=False)}", 900)
    fmt = lambda t: dt.datetime.fromtimestamp(t, TZ).strftime("%d/%m %H:%M") if t else "em andamento"
    rows = "".join(f"<tr><td>{html.escape(s['site'])}<td>{s['uptime']}%<td>{s['avg_ms']} ms<td>{s['p95_ms']} ms"
                   f"<td>{html.escape(', '.join(f'{k}×{v}' for k, v in s['issues'].items()) or '—')}</tr>" for s in stats)
    irows = "".join(f"<tr><td>{html.escape(i['site'])}<td>{fmt(i['started'])}<td>{fmt(i['ended'])}"
                    f"<td>{html.escape(i['reason'] or '')}</tr>" for i in recent) or "<tr><td colspan=4>Nenhum incidente 🎉</tr>"
    doc = f"""<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>Relatório de monitoramento</title>
<style>body{{font:15px system-ui;max-width:900px;margin:2rem auto;padding:0 1rem;color:#1a1a1a}}
table{{border-collapse:collapse;width:100%;margin:1rem 0}}td,th{{border-bottom:1px solid #ddd;padding:.5rem;text-align:left}}
.ai{{background:#f3f0ff;padding:1rem;border-radius:8px;white-space:pre-wrap}}</style>
<h1>Relatório de monitoramento · Luuna</h1><p>Últimas 24h · gerado em {local:%d/%m/%Y %H:%M}</p>
{f'<h2>Análise da IA</h2><div class=ai>{html.escape(summary)}</div>' if summary else ''}
<h2>Disponibilidade e performance</h2><table><tr><th>Página<th>Uptime<th>Média<th>P95<th>Problemas</tr>{rows}</table>
<h2>Incidentes</h2><table><tr><th>Página<th>Início<th>Fim<th>Motivo</tr>{irows}</table>"""
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

    cut = now - 48 * 3600
    history = [h for h in history if h["ts"] > cut]
    daily = {k: daily[k] for k in sorted(daily)[-120:]}
    if mode != "browser" and (local.hour, local.minute) >= tuple(map(int, CFG.get("report_time", "08:00").split(":"))) \
            and st.get("_last_report") != day:
        st["_last_report"] = day
        await make_report(history, incs, local)
    save("history", history); save("daily", daily); save("incidents", incs[:300]); save("state", st)
    save("status", build_status(history))
    print(f"ok: {len(results)} checagens ({mode}), {sum(r['state'] == 'down' for r in results)} com problema")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["http", "browser"], default="http")
    asyncio.run(main(ap.parse_args().mode))
