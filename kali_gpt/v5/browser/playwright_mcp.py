#!/usr/bin/env python3
"""
Playwright browser automation for Kali-GPT v5 validation.

This module keeps browser-backed proof collection reusable outside the
exploitation engine, including screenshots and JavaScript dialog evidence.
"""

import asyncio
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlencode, urljoin


@dataclass
class BrowserEvidence:
    url: str
    screenshot: Optional[bytes]
    console_logs: List[str] = field(default_factory=list)
    dialogs: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    captured_at: datetime = field(default_factory=datetime.now)


class PlaywrightMCPBrowser:
    """Small Playwright wrapper for XSS and authentication validation."""

    def __init__(
        self,
        headless: bool = True,
        proxy: Optional[str] = None,
        screenshot_dir: Optional[str] = None,
        timeout_ms: int = 15000,
    ):
        self.headless = headless
        self.proxy = proxy
        self.screenshot_dir = Path(screenshot_dir) if screenshot_dir else None
        self.timeout_ms = timeout_ms
        self._playwright = None
        self.browser = None
        self.context = None
        self.page = None

    async def start(self):
        if self.page:
            return
        try:
            from playwright.async_api import async_playwright
        except ImportError as exc:
            raise RuntimeError("Playwright not installed. Run: pip install playwright && playwright install") from exc

        self._playwright = await async_playwright().start()
        launch_args: Dict[str, Any] = {"headless": self.headless}
        if self.proxy:
            launch_args["proxy"] = {"server": self.proxy}
        self.browser = await self._playwright.chromium.launch(**launch_args)
        self.context = await self.browser.new_context(ignore_https_errors=True)
        self.context.set_default_timeout(self.timeout_ms)
        self.page = await self.context.new_page()

    async def validate_xss(self, target_url: str, endpoint: str, parameter: Optional[str], payload: str) -> Tuple[bool, BrowserEvidence]:
        await self.start()
        url = self._build_url(target_url, endpoint, parameter, payload)
        evidence = BrowserEvidence(url=url, screenshot=None, metadata={"payload": payload, "parameter": parameter})

        self.page.on("console", lambda msg: evidence.console_logs.append(msg.text))

        async def handle_dialog(dialog):
            evidence.dialogs.append(dialog.message)
            await dialog.dismiss()

        self.page.on("dialog", handle_dialog)
        await self.page.goto(url, wait_until="domcontentloaded")
        await asyncio.sleep(1.5)
        evidence.screenshot = await self._screenshot("xss")
        return bool(evidence.dialogs), evidence

    async def validate_auth_form(
        self,
        target_url: str,
        endpoint: str,
        username: str,
        password: str,
        username_field: str = "username",
        password_field: str = "password",
    ) -> Tuple[bool, BrowserEvidence]:
        await self.start()
        url = urljoin(target_url, endpoint or "")
        evidence = BrowserEvidence(url=url, screenshot=None, metadata={"username": username, "endpoint": endpoint})
        await self.page.goto(url, wait_until="domcontentloaded")
        await self.page.fill(f'input[name="{username_field}"]', username)
        await self.page.fill(f'input[name="{password_field}"]', password)
        await self.page.press(f'input[name="{password_field}"]', "Enter")
        await asyncio.sleep(1.5)
        body = (await self.page.content()).lower()
        current_url = self.page.url.lower()
        evidence.screenshot = await self._screenshot("auth")
        success_terms = ("dashboard", "welcome", "logout", "profile", "admin")
        failure_terms = ("invalid", "incorrect", "failed", "wrong")
        success = any(term in body or term in current_url for term in success_terms) and not any(term in body for term in failure_terms)
        return success, evidence

    def _build_url(self, target_url: str, endpoint: str, parameter: Optional[str], payload: str) -> str:
        url = urljoin(target_url, endpoint or "")
        if not parameter:
            return url
        separator = "&" if "?" in url else "?"
        return f"{url}{separator}{urlencode({parameter: payload})}"

    async def _screenshot(self, prefix: str) -> bytes:
        screenshot = await self.page.screenshot(full_page=True)
        if self.screenshot_dir:
            self.screenshot_dir.mkdir(parents=True, exist_ok=True)
            path = self.screenshot_dir / f"{prefix}_{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}.png"
            path.write_bytes(screenshot)
        return screenshot

    async def close(self):
        if self.page:
            await self.page.close()
            self.page = None
        if self.context:
            await self.context.close()
            self.context = None
        if self.browser:
            await self.browser.close()
            self.browser = None
        if self._playwright:
            await self._playwright.stop()
            self._playwright = None


__all__ = ["BrowserEvidence", "PlaywrightMCPBrowser"]
