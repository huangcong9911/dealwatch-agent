"""DealWatch sandbox runner.

This file is the ONLY code that executes inside the disposable sandbox
container. It receives a job (JSON on stdin), drives a real headless Chromium
with Playwright, and prints one JSON result line on stdout.

It never receives API keys or credentials: the control plane keeps the Vultr
Serverless Inference key on the host, and the container is started with an
empty environment.
"""
import base64
import ipaddress
import json
import os
import socket
import sys
import time
import urllib.parse

MAX_TEXT = 12000
ALLOWED_ACTIONS = {"goto", "click_text", "scroll", "wait", "extract"}


def _host_of(url):
    try:
        return (urllib.parse.urlparse(url).hostname or "").lower()
    except Exception:
        return ""


def _host_allowed(host, allowed):
    if not host:
        return False
    for a in allowed:
        a = a.lower().lstrip(".")
        if host == a or host.endswith("." + a):
            return True
    return False


def _is_private_literal(host):
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return ip.is_private or ip.is_link_local or ip.is_loopback or ip.is_reserved


def _default_gateway():
    try:
        with open("/proc/net/route") as f:
            for line in f.readlines()[1:]:
                p = line.split()
                if p[1] == "00000000":
                    g = int(p[2], 16)
                    return socket.inet_ntoa(g.to_bytes(4, "little"))
    except Exception:
        pass
    return None


def containment_probes():
    """Actively try to break out, and record that each attempt fails."""
    out = []

    secrets = [k for k in os.environ if any(s in k.upper() for s in ("KEY", "TOKEN", "SECRET", "PASSWORD", "VULTR"))]
    out.append({
        "check": "Secrets in sandbox environment",
        "attempt": "scan os.environ for API keys / tokens",
        "contained": not secrets,
        "detail": "no credentials present" if not secrets else "FOUND: " + ", ".join(secrets),
    })

    def tcp(host, port):
        t = time.time()
        try:
            s = socket.create_connection((host, port), timeout=3)
            s.close()
            return False, "connected (NOT contained)"
        except Exception as e:  # noqa: BLE001
            return True, "%s after %.1fs" % (type(e).__name__, time.time() - t)

    ok, d = tcp("169.254.169.254", 80)
    out.append({"check": "Cloud metadata endpoint", "attempt": "TCP 169.254.169.254:80 (instance metadata / credentials)", "contained": ok, "detail": d})

    gw = _default_gateway()
    if gw:
        ok, d = tcp(gw, 8000)
        out.append({"check": "Host control plane", "attempt": "TCP %s:8000 (the agent's own API on the host)" % gw, "contained": ok, "detail": d})
        ok, d = tcp(gw, 22)
        out.append({"check": "Host SSH", "attempt": "TCP %s:22" % gw, "contained": ok, "detail": d})

    try:
        with open("/etc/dealwatch-escape-test", "w") as f:
            f.write("x")
        out.append({"check": "Root filesystem write", "attempt": "write /etc/dealwatch-escape-test", "contained": False, "detail": "write succeeded (NOT contained)"})
    except Exception as e:  # noqa: BLE001
        out.append({"check": "Root filesystem write", "attempt": "write /etc/dealwatch-escape-test", "contained": True, "detail": type(e).__name__ + ": " + str(e)[:80]})

    try:
        os.stat("/var/run/docker.sock")
        out.append({"check": "Docker socket", "attempt": "access /var/run/docker.sock", "contained": False, "detail": "socket visible (NOT contained)"})
    except Exception:
        out.append({"check": "Docker socket", "attempt": "access /var/run/docker.sock", "contained": True, "detail": "not mounted"})

    uid = os.getuid()
    out.append({"check": "Unprivileged user", "attempt": "check uid", "contained": uid != 0, "detail": "uid=%d" % uid})

    try:
        kernel = os.uname().release
    except Exception:
        kernel = "?"
    mem = "?"
    for p in ("/sys/fs/cgroup/memory.max", "/sys/fs/cgroup/memory/memory.limit_in_bytes"):
        try:
            v = open(p).read().strip()
            mem = v if v == "max" else "%d MiB" % (int(v) // 1048576)
            break
        except Exception:
            continue
    out.append({"check": "Kernel / runtime", "attempt": "uname -r (gVisor reports its own user-space kernel)", "contained": True, "detail": "kernel=%s, memory cap=%s" % (kernel, mem)})
    return out


def run(job):
    from playwright.sync_api import sync_playwright

    allowed = [h.lower() for h in job.get("allowed_hosts", [])]
    steps = [s for s in job.get("steps", []) if s.get("action") in ALLOWED_ACTIONS][: int(job.get("max_steps", 8))]
    log, blocked, console = [], [], []
    result = {"ok": False, "log": log, "blocked": blocked, "console": console}
    t0 = time.time()

    with sync_playwright() as p:
        browser = p.chromium.launch(args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"])
        ctx = browser.new_context(viewport={"width": 1280, "height": 900}, user_agent=(
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36 DealWatchAgent/1.0"))
        page = ctx.new_page()
        page.set_default_timeout(20000)

        def on_route(route):
            req = route.request
            host = _host_of(req.url)
            if req.url.startswith(("data:", "blob:", "about:")):
                return route.continue_()
            if _is_private_literal(host):
                blocked.append({"url": req.url[:200], "why": "private / link-local address", "type": req.resource_type})
                return route.abort()
            if req.is_navigation_request() and req.frame == page.main_frame and not _host_allowed(host, allowed):
                blocked.append({"url": req.url[:200], "why": "navigation outside allow-list", "type": "navigation"})
                return route.abort()
            if host.endswith((".example", ".invalid", ".attacker")) or "exfil" in req.url.lower():
                blocked.append({"url": req.url[:200], "why": "exfiltration pattern", "type": req.resource_type})
                return route.abort()
            return route.continue_()

        page.route("**/*", on_route)
        page.on("console", lambda m: console.append(m.text[:300]) if len(console) < 40 else None)

        if job.get("fixture_html"):
            page.set_content(job["fixture_html"], wait_until="load")
            page.wait_for_timeout(2500)
            log.append({"action": "load_fixture", "ok": True, "detail": "untrusted page loaded from fixture"})

        for s in steps:
            a = s["action"]
            try:
                if a == "goto":
                    url = s.get("url") or job.get("url")
                    if not _host_allowed(_host_of(url), allowed):
                        blocked.append({"url": url, "why": "planner asked for host outside allow-list", "type": "plan"})
                        log.append({"action": a, "ok": False, "detail": "refused: %s not in allow-list" % _host_of(url)})
                        continue
                    page.goto(url, wait_until="domcontentloaded")
                    try:
                        page.wait_for_load_state("networkidle", timeout=8000)
                    except Exception:
                        pass
                    log.append({"action": a, "ok": True, "detail": page.url[:200]})
                elif a == "click_text":
                    txt = str(s.get("text", ""))[:80]
                    page.get_by_text(txt, exact=False).first.click(timeout=6000)
                    page.wait_for_timeout(1500)
                    log.append({"action": a, "ok": True, "detail": txt})
                elif a == "scroll":
                    for _ in range(min(int(s.get("times", 2)), 6)):
                        page.mouse.wheel(0, 1600)
                        page.wait_for_timeout(500)
                    log.append({"action": a, "ok": True, "detail": "scrolled"})
                elif a == "wait":
                    page.wait_for_timeout(min(int(s.get("ms", 1000)), 5000))
                    log.append({"action": a, "ok": True, "detail": "waited"})
                elif a == "extract":
                    log.append({"action": a, "ok": True, "detail": "captured"})
            except Exception as e:  # noqa: BLE001
                log.append({"action": a, "ok": False, "detail": str(e).splitlines()[0][:200]})

        try:
            text = page.inner_text("body")
        except Exception:
            text = ""
        links = []
        try:
            links = page.eval_on_selector_all(
                "a[href]", "els => els.slice(0, 400).map(e => [e.innerText.trim().slice(0,80), e.href]).filter(x => x[0])")
        except Exception:
            pass
        page.evaluate("window.scrollTo(0,0)")
        shot = page.screenshot(type="jpeg", quality=60, full_page=False)
        result.update({
            "ok": True,
            "title": page.title()[:200],
            "final_url": page.url[:300],
            "text": text[:MAX_TEXT],
            "links": links[:80],
            "screenshot_b64": base64.b64encode(shot).decode(),
        })
        browser.close()

    result["probes"] = containment_probes() if job.get("probe", True) else []
    result["elapsed_s"] = round(time.time() - t0, 1)
    return result


if __name__ == "__main__":
    try:
        res = run(json.loads(sys.stdin.read() or "{}"))
    except Exception as e:  # noqa: BLE001
        res = {"ok": False, "error": "%s: %s" % (type(e).__name__, e), "probes": containment_probes()}
    sys.stdout.write("DWRESULT:" + json.dumps(res) + "\n")
    sys.stdout.flush()
