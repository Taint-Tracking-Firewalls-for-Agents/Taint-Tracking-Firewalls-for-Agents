"""Capture high-fidelity screenshots of agent-firewall-dye in Light and Dark modes at Desktop and Mobile widths."""
import asyncio
import base64
import json
from pathlib import Path
import subprocess
import time
import urllib.request
import websockets

HTML_PATH = Path(__file__).resolve().parent / "app" / "agent-firewall-dye.html"
OUTPUT_DIR = Path(__file__).resolve().parent / "benchmarks" / "results"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

CHROME_PATH = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
USER_DATA = Path(__file__).resolve().parent / "chrome_shot_profile"

async def capture_cdp(ws_url, theme, width, height, out_file):
    async with websockets.connect(ws_url, max_size=50_000_000) as ws:
        msg_id = 1
        
        async def send(method, params=None):
            nonlocal msg_id
            msg_id += 1
            payload = {"id": msg_id, "method": method, "params": params or {}}
            await ws.send(json.dumps(payload))
            while True:
                resp = json.loads(await ws.recv())
                if resp.get("id") == msg_id:
                    return resp.get("result", {})

        # Set device viewport metrics
        await send("Emulation.setDeviceMetricsOverride", {
            "width": width,
            "height": height,
            "deviceScaleFactor": 2,
            "mobile": width < 600
        })

        # Navigate to file
        file_url = HTML_PATH.as_uri()
        await send("Page.navigate", {"url": file_url})
        await asyncio.sleep(2.8) # Wait for fill animation and stamp slam

        # Apply theme attribute directly
        await send("Runtime.evaluate", {
            "expression": f"setTheme('{theme}');"
        })
        await asyncio.sleep(0.4)

        # Capture screenshot
        res = await send("Page.captureScreenshot", {"format": "png", "captureBeyondViewport": False})
        data = base64.b64decode(res["data"])
        with open(out_file, "wb") as f:
            f.write(data)
        print(f"Captured: {out_file.name} ({width}x{height}, {theme})")

async def main():
    proc = subprocess.Popen([
        CHROME_PATH,
        "--headless=new",
        "--remote-debugging-port=9222",
        "--disable-gpu",
        f"--user-data-dir={USER_DATA}"
    ])
    time.sleep(2.0)
    try:
        with urllib.request.urlopen("http://127.0.0.1:9222/json") as r:
            tabs = json.loads(r.read().decode())
        ws_url = tabs[0]["webSocketDebuggerUrl"]

        tasks = [
            ("dark", 1200, 920, OUTPUT_DIR / "screenshot_desktop_dark.png"),
            ("light", 1200, 920, OUTPUT_DIR / "screenshot_desktop_light.png"),
            ("dark", 390, 844, OUTPUT_DIR / "screenshot_mobile_dark.png"),
            ("light", 390, 844, OUTPUT_DIR / "screenshot_mobile_light.png"),
        ]

        for theme, w, h, out in tasks:
            await capture_cdp(ws_url, theme, w, h, out)

    finally:
        proc.terminate()

if __name__ == "__main__":
    asyncio.run(main())
