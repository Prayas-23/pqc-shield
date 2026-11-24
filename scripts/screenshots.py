"""Screenshots of the web UI (docs/screens/) with Chrome driven over the DevTools protocol in real time.

Run with the API (make api) and the UI (make web) already running:  .venv/Scripts/python scripts/screenshots.py
Playwright is not an approved dependency, so this uses the installed Chrome and the `websockets` package. It only
loads pages and reads pixels; it starts no capture and writes only the PNG files.
"""

from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

from websockets.sync.client import connect

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs" / "screens"
BASE = "http://localhost:5173"
PORT = 9333
CHROME_CANDIDATES = [r"C:\Program Files\Google\Chrome\Application\chrome.exe",
                     r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"]
# (file stem, url, wait seconds before the picture)
SCREENS = [("1-ladder", "/#ladder", 5.5), ("2-drift", "/#drift", 4), ("3-detectors", "/#detectors", 6),
           ("4-replay", "/?autostart=1#replay", 4), ("5-caveats", "/#caveats", 2)]


class Cdp:
    def __init__(self, ws_url: str) -> None:
        self.ws = connect(ws_url, max_size=64 * 1024 * 1024)
        self.n = 0

    def call(self, method: str, **params) -> dict:
        self.n += 1
        self.ws.send(json.dumps({"id": self.n, "method": method, "params": params}))
        while True:
            msg = json.loads(self.ws.recv())
            if msg.get("id") == self.n:
                if "error" in msg:
                    raise RuntimeError(f"{method}: {msg['error']}")
                return msg.get("result", {})


def start_chrome() -> subprocess.Popen:
    exe = next((c for c in CHROME_CANDIDATES if os.path.exists(c)), None)
    if exe is None:
        raise SystemExit("Chrome/Edge not found")
    prof = tempfile.mkdtemp(prefix="pqdl-shots-")
    return subprocess.Popen([exe, "--headless=new", "--disable-gpu", "--hide-scrollbars", f"--remote-debugging-port={PORT}",
                             f"--user-data-dir={prof}", "--no-first-run", "about:blank"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def page_ws() -> str:
    for _ in range(50):
        try:
            tabs = json.load(urllib.request.urlopen(f"http://127.0.0.1:{PORT}/json"))
            page = next(t for t in tabs if t.get("type") == "page")
            return page["webSocketDebuggerUrl"]
        except Exception:
            time.sleep(0.2)
    raise SystemExit("could not reach Chrome DevTools")


LAYOUT_CHECK = """(() => { const out = []; document.querySelectorAll('.wbody,.pane,.pbody,.heatwrap,.ladder,.seqwrap,.view,.workspace,.cols2,.panes2,.help,.top,.status').forEach(e => {
  if (e.scrollHeight > e.clientHeight + 1 || e.scrollWidth > e.clientWidth + 1) out.push(e.className.split(' ')[0] + ' content ' + e.scrollWidth + 'x' + e.scrollHeight + ' in box ' + e.clientWidth + 'x' + e.clientHeight); });
  const d = document.documentElement; out.unshift('page ' + d.scrollWidth + 'x' + d.scrollHeight + ' in window ' + innerWidth + 'x' + innerHeight); return out.join(' | '); })()"""


def shoot(cdp: Cdp, url: str, width: int, height: int, wait: float, path: Path, script: str = "") -> None:
    cdp.call("Emulation.setDeviceMetricsOverride", width=width, height=height, deviceScaleFactor=1, mobile=width < 600)
    cdp.call("Page.navigate", url="about:blank")
    cdp.call("Page.navigate", url=BASE + url)
    time.sleep(wait)
    if script:                                    # e.g. pick a select value or click a toggle, then wait for the page to react
        cdp.call("Runtime.evaluate", expression=script)
        time.sleep(2)
    report = cdp.call("Runtime.evaluate", expression=LAYOUT_CHECK)["result"]["value"]
    data = cdp.call("Page.captureScreenshot", format="png")["data"]
    path.write_bytes(base64.b64decode(data))
    print("wrote", path.relative_to(ROOT), "|", report)


SET_APP_VIEW = """(() => { const s = [...document.querySelectorAll('select')].find(x => [...x.options].some(o => o.value === 'app'));
  Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, 'value').set.call(s, 'app'); s.dispatchEvent(new Event('change', {bubbles: true})); })()"""
OPEN_HELP = "document.querySelector('.titlebar button').click()"


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    chrome = start_chrome()
    try:
        cdp = Cdp(page_ws())
        cdp.call("Page.enable")
        for stem, url, wait in SCREENS:
            shoot(cdp, url, 1280, 800, wait, OUT / f"{stem}-1280x800.png")
            shoot(cdp, url, 390, 844, wait, OUT / f"{stem}-phone-390x844.png")
        shoot(cdp, "/#ladder", 1280, 800, 2, OUT / "1-ladder-measured-overhead-1280x800.png", script="document.querySelector('input[type=checkbox]').click()")
        shoot(cdp, "/#drift", 1280, 800, 4, OUT / "2-drift-application-view-1280x800.png", script=SET_APP_VIEW)
        shoot(cdp, "/#detectors", 1280, 800, 6, OUT / "3-detectors-help-open-1280x800.png", script=OPEN_HELP)
        shoot(cdp, "/#drift", 1280, 800, 0.12, OUT / "2-drift-loading-1280x800.png")
        shoot(cdp, "/#replay", 1280, 800, 1.5, OUT / "4-replay-idle-1280x800.png")
    finally:
        chrome.terminate()
    return 0


if __name__ == "__main__":
    sys.exit(main())
