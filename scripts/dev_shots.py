#!/usr/bin/env python3
"""Dev-only helper: log into a running panel and screenshot a few views.

    .venv/bin/python scripts/dev_shots.py http://localhost:5173 /tmp/shots "/,/tools"
"""
import os
import sys
from pathlib import Path

from playwright.sync_api import sync_playwright

BASE = (sys.argv[1] if len(sys.argv) > 1 else "http://localhost:5173").rstrip("/")
OUT = Path(sys.argv[2] if len(sys.argv) > 2 else "/tmp/shots")
OUT.mkdir(parents=True, exist_ok=True)
ROUTES = (sys.argv[3] if len(sys.argv) > 3 else "/").split(",")
USER = os.environ.get("SHOT_USER", "admin")
PASSWORD = os.environ.get("SHOT_PASSWORD", "DevPassw0rd!2026")

with sync_playwright() as p:
    browser = p.chromium.launch()
    page = browser.new_page(viewport={"width": 1440, "height": 900})
    page.on("console", lambda m: print("console:", m.type, m.text[:200]))
    page.on("pageerror", lambda e: print("pageerror:", str(e)[:300]))
    page.goto(BASE + "/", wait_until="networkidle")
    page.wait_for_timeout(1500)
    if page.locator('input[type="password"]').count():
        page.fill('input[autocomplete="username"]', USER)
        page.fill('input[autocomplete="current-password"]', PASSWORD)
        page.click("button.login-submit")
        page.wait_for_timeout(4000)
        page.screenshot(path=str(OUT / "after-login.png"))
        print("logged in, password fields left:", page.locator('input[type="password"]').count())
    for route in ROUTES:
        page.goto(BASE + route, wait_until="networkidle")
        page.wait_for_timeout(2500)
        name = route.strip("/").replace("/", "-") or "dashboard"
        page.screenshot(path=str(OUT / f"{name}.png"), full_page=True)
        print("shot:", name)
    browser.close()
