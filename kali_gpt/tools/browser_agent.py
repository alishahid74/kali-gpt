"""
Kali-GPT Browser Automation Module

Headless browser automation for web testing:
- Screenshot capture
- DOM analysis
- Form detection
- JavaScript execution
- Network traffic monitoring
- Security header analysis
"""

import asyncio
import json
import base64
import os
from datetime import datetime
from dataclasses import dataclass
from typing import List, Dict, Optional, Any
from pathlib import Path

try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.chrome.service import Service
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.common.exceptions import TimeoutException, WebDriverException
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False

try:
    from playwright.async_api import async_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()


@dataclass
class BrowserResult:
    """Result from browser operation"""
    url: str
    title: str
    status_code: int
    headers: Dict[str, str]
    cookies: List[Dict]
    forms: List[Dict]
    links: List[str]
    scripts: List[str]
    security_headers: Dict[str, Any]
    screenshot_path: Optional[str]
    dom_info: Dict
    technologies: List[str]
    errors: List[str]


class BrowserAgent:
    """
    Headless browser agent for web security testing.
    Supports both Selenium and Playwright.
    """
    
    def __init__(self, headless: bool = True, proxy: str = None):
        self.headless = headless
        self.proxy = proxy
        self.driver = None
        self.playwright = None
        self.browser = None
        self.output_dir = Path.home() / ".kali-gpt" / "browser"
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    async def init_selenium(self):
        """Initialize Selenium Chrome driver"""
        if not SELENIUM_AVAILABLE:
            raise ImportError("Selenium not installed. Run: pip install selenium")
        
        options = Options()
        
        if self.headless:
            options.add_argument("--headless=new")
        
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--disable-gpu")
        options.add_argument("--window-size=1920,1080")
        options.add_argument("--ignore-certificate-errors")
        options.add_argument("--disable-web-security")
        options.add_argument("--allow-running-insecure-content")
        
        # User agent
        options.add_argument("--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
        
        if self.proxy:
            options.add_argument(f"--proxy-server={self.proxy}")
        
        # Enable performance logging
        options.set_capability("goog:loggingPrefs", {"performance": "ALL"})
        
        try:
            self.driver = webdriver.Chrome(options=options)
            self.driver.set_page_load_timeout(30)
            return True
        except Exception as e:
            console.print(f"[red]Failed to init Chrome: {e}[/red]")
            return False
    
    async def init_playwright(self):
        """Initialize Playwright browser"""
        if not PLAYWRIGHT_AVAILABLE:
            raise ImportError("Playwright not installed. Run: pip install playwright && playwright install")
        
        self.playwright = await async_playwright().start()
        
        browser_args = ["--disable-web-security"]
        if self.proxy:
            browser_args.append(f"--proxy-server={self.proxy}")
        
        self.browser = await self.playwright.chromium.launch(
            headless=self.headless,
            args=browser_args
        )
        return True
    
    async def close(self):
        """Close browser"""
        if self.driver:
            self.driver.quit()
            self.driver = None
        
        if self.browser:
            await self.browser.close()
            self.browser = None
        
        if self.playwright:
            await self.playwright.stop()
            self.playwright = None
    
    async def analyze_url(self, url: str) -> BrowserResult:
        """
        Comprehensive URL analysis.
        """
        errors = []
        
        # Initialize browser
        if SELENIUM_AVAILABLE:
            if not self.driver:
                await self.init_selenium()
        elif PLAYWRIGHT_AVAILABLE:
            if not self.browser:
                await self.init_playwright()
        else:
            return BrowserResult(
                url=url,
                title="",
                status_code=0,
                headers={},
                cookies=[],
                forms=[],
                links=[],
                scripts=[],
                security_headers={},
                screenshot_path=None,
                dom_info={},
                technologies=[],
                errors=["No browser engine available. Install selenium or playwright."]
            )
        
        if SELENIUM_AVAILABLE and self.driver:
            return await self._analyze_selenium(url)
        else:
            return await self._analyze_playwright(url)
    
    async def _analyze_selenium(self, url: str) -> BrowserResult:
        """Analyze URL with Selenium"""
        errors = []
        
        try:
            self.driver.get(url)
            WebDriverWait(self.driver, 10).until(
                EC.presence_of_element_located((By.TAG_NAME, "body"))
            )
        except TimeoutException:
            errors.append("Page load timeout")
        except Exception as e:
            errors.append(f"Navigation error: {str(e)}")
        
        # Get basic info
        title = self.driver.title or ""
        
        # Get cookies
        cookies = self.driver.get_cookies()
        
        # Get forms
        forms = []
        try:
            form_elements = self.driver.find_elements(By.TAG_NAME, "form")
            for form in form_elements:
                form_info = {
                    "action": form.get_attribute("action") or "",
                    "method": form.get_attribute("method") or "GET",
                    "inputs": []
                }
                
                inputs = form.find_elements(By.TAG_NAME, "input")
                for inp in inputs:
                    form_info["inputs"].append({
                        "name": inp.get_attribute("name") or "",
                        "type": inp.get_attribute("type") or "text",
                        "id": inp.get_attribute("id") or ""
                    })
                
                forms.append(form_info)
        except:
            errors.append("Failed to extract forms")
        
        # Get links
        links = []
        try:
            link_elements = self.driver.find_elements(By.TAG_NAME, "a")
            for link in link_elements[:100]:  # Limit
                href = link.get_attribute("href")
                if href:
                    links.append(href)
        except:
            errors.append("Failed to extract links")
        
        # Get scripts
        scripts = []
        try:
            script_elements = self.driver.find_elements(By.TAG_NAME, "script")
            for script in script_elements:
                src = script.get_attribute("src")
                if src:
                    scripts.append(src)
        except:
            pass
        
        # Take screenshot
        screenshot_path = None
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            screenshot_path = str(self.output_dir / f"screenshot_{timestamp}.png")
            self.driver.save_screenshot(screenshot_path)
        except:
            errors.append("Failed to capture screenshot")
        
        # Detect technologies
        technologies = self._detect_technologies(self.driver.page_source)
        
        # DOM info
        dom_info = {
            "forms_count": len(forms),
            "links_count": len(links),
            "scripts_count": len(scripts),
            "iframes": len(self.driver.find_elements(By.TAG_NAME, "iframe")),
            "inputs": len(self.driver.find_elements(By.TAG_NAME, "input")),
        }
        
        # Get response headers from performance logs
        headers = {}
        security_headers = {}
        status_code = 200
        
        try:
            logs = self.driver.get_log("performance")
            for log in logs:
                message = json.loads(log["message"])
                if "Network.responseReceived" in str(message):
                    params = message.get("message", {}).get("params", {})
                    response = params.get("response", {})
                    if response.get("url") == url:
                        headers = response.get("headers", {})
                        status_code = response.get("status", 200)
                        break
        except:
            pass
        
        # Analyze security headers
        security_headers = self._analyze_security_headers(headers)
        
        return BrowserResult(
            url=url,
            title=title,
            status_code=status_code,
            headers=headers,
            cookies=cookies,
            forms=forms,
            links=links,
            scripts=scripts,
            security_headers=security_headers,
            screenshot_path=screenshot_path,
            dom_info=dom_info,
            technologies=technologies,
            errors=errors
        )
    
    async def _analyze_playwright(self, url: str) -> BrowserResult:
        """Analyze URL with Playwright"""
        errors = []
        
        page = await self.browser.new_page()
        
        # Capture response headers
        headers = {}
        status_code = 200
        
        async def handle_response(response):
            nonlocal headers, status_code
            if response.url == url:
                headers = await response.all_headers()
                status_code = response.status
        
        page.on("response", handle_response)
        
        try:
            await page.goto(url, timeout=30000)
            await page.wait_for_load_state("networkidle")
        except Exception as e:
            errors.append(f"Navigation error: {str(e)}")
        
        # Get basic info
        title = await page.title()
        
        # Get cookies
        cookies = await page.context.cookies()
        
        # Get forms
        forms = await page.evaluate("""
            () => {
                return Array.from(document.forms).map(form => ({
                    action: form.action,
                    method: form.method,
                    inputs: Array.from(form.elements).filter(e => e.tagName === 'INPUT').map(i => ({
                        name: i.name,
                        type: i.type,
                        id: i.id
                    }))
                }))
            }
        """)
        
        # Get links
        links = await page.evaluate("""
            () => Array.from(document.querySelectorAll('a[href]'))
                    .map(a => a.href)
                    .slice(0, 100)
        """)
        
        # Get scripts
        scripts = await page.evaluate("""
            () => Array.from(document.querySelectorAll('script[src]'))
                    .map(s => s.src)
        """)
        
        # Take screenshot
        screenshot_path = None
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            screenshot_path = str(self.output_dir / f"screenshot_{timestamp}.png")
            await page.screenshot(path=screenshot_path, full_page=True)
        except:
            errors.append("Failed to capture screenshot")
        
        # Get page content for technology detection
        content = await page.content()
        technologies = self._detect_technologies(content)
        
        # DOM info
        dom_info = await page.evaluate("""
            () => ({
                forms_count: document.forms.length,
                links_count: document.querySelectorAll('a').length,
                scripts_count: document.querySelectorAll('script').length,
                iframes: document.querySelectorAll('iframe').length,
                inputs: document.querySelectorAll('input').length,
            })
        """)
        
        # Security headers
        security_headers = self._analyze_security_headers(headers)
        
        await page.close()
        
        return BrowserResult(
            url=url,
            title=title,
            status_code=status_code,
            headers=headers,
            cookies=[dict(c) for c in cookies],
            forms=forms,
            links=links,
            scripts=scripts,
            security_headers=security_headers,
            screenshot_path=screenshot_path,
            dom_info=dom_info,
            technologies=technologies,
            errors=errors
        )
    
    def _detect_technologies(self, html: str) -> List[str]:
        """Detect technologies from HTML"""
        technologies = []
        html_lower = html.lower()
        
        tech_signatures = {
            "WordPress": ["wp-content", "wp-includes", "wordpress"],
            "Drupal": ["drupal", "sites/default"],
            "Joomla": ["joomla", "com_content"],
            "React": ["react", "_reactroot", "data-reactroot"],
            "Angular": ["ng-app", "angular", "ng-controller"],
            "Vue.js": ["vue.js", "v-bind", "v-model"],
            "jQuery": ["jquery"],
            "Bootstrap": ["bootstrap"],
            "PHP": [".php", "phpsessid"],
            "ASP.NET": ["aspnet", "__viewstate", ".aspx"],
            "Node.js": ["node.js", "express"],
            "Nginx": ["nginx"],
            "Apache": ["apache"],
            "Cloudflare": ["cloudflare"],
            "Google Analytics": ["google-analytics", "gtag"],
            "reCAPTCHA": ["recaptcha"],
        }
        
        for tech, signatures in tech_signatures.items():
            for sig in signatures:
                if sig in html_lower:
                    if tech not in technologies:
                        technologies.append(tech)
                    break
        
        return technologies
    
    def _analyze_security_headers(self, headers: Dict) -> Dict:
        """Analyze security headers"""
        headers_lower = {k.lower(): v for k, v in headers.items()}
        
        security_headers = {
            "x-frame-options": {
                "present": "x-frame-options" in headers_lower,
                "value": headers_lower.get("x-frame-options", ""),
                "recommendation": "DENY or SAMEORIGIN"
            },
            "x-content-type-options": {
                "present": "x-content-type-options" in headers_lower,
                "value": headers_lower.get("x-content-type-options", ""),
                "recommendation": "nosniff"
            },
            "x-xss-protection": {
                "present": "x-xss-protection" in headers_lower,
                "value": headers_lower.get("x-xss-protection", ""),
                "recommendation": "1; mode=block"
            },
            "strict-transport-security": {
                "present": "strict-transport-security" in headers_lower,
                "value": headers_lower.get("strict-transport-security", ""),
                "recommendation": "max-age=31536000; includeSubDomains"
            },
            "content-security-policy": {
                "present": "content-security-policy" in headers_lower,
                "value": headers_lower.get("content-security-policy", "")[:100],
                "recommendation": "Define strict CSP"
            },
            "referrer-policy": {
                "present": "referrer-policy" in headers_lower,
                "value": headers_lower.get("referrer-policy", ""),
                "recommendation": "strict-origin-when-cross-origin"
            },
            "permissions-policy": {
                "present": "permissions-policy" in headers_lower,
                "value": headers_lower.get("permissions-policy", "")[:100],
                "recommendation": "Restrict sensitive features"
            },
        }
        
        # Calculate score
        present_count = sum(1 for h in security_headers.values() if h["present"])
        security_headers["score"] = f"{present_count}/7"
        security_headers["rating"] = "Good" if present_count >= 5 else "Fair" if present_count >= 3 else "Poor"
        
        return security_headers
    
    async def execute_javascript(self, url: str, script: str) -> Any:
        """Execute JavaScript on a page"""
        if not self.driver and not self.browser:
            await self.init_selenium() if SELENIUM_AVAILABLE else await self.init_playwright()
        
        if self.driver:
            self.driver.get(url)
            return self.driver.execute_script(script)
        elif self.browser:
            page = await self.browser.new_page()
            await page.goto(url)
            result = await page.evaluate(script)
            await page.close()
            return result
    
    async def fill_and_submit_form(self, url: str, form_data: Dict) -> BrowserResult:
        """Fill and submit a form"""
        if not self.driver and not self.browser:
            await self.init_selenium() if SELENIUM_AVAILABLE else await self.init_playwright()
        
        if self.driver:
            self.driver.get(url)
            
            for field_name, value in form_data.items():
                try:
                    element = self.driver.find_element(By.NAME, field_name)
                    element.clear()
                    element.send_keys(value)
                except:
                    pass
            
            # Submit
            try:
                submit = self.driver.find_element(By.CSS_SELECTOR, "input[type='submit'], button[type='submit']")
                submit.click()
            except:
                pass
            
            # Analyze result
            return await self._analyze_selenium(self.driver.current_url)
        
        return None


def display_browser_result(result: BrowserResult):
    """Display browser analysis results"""
    
    console.print(Panel(
        f"[bold]URL:[/bold] {result.url}\n"
        f"[bold]Title:[/bold] {result.title}\n"
        f"[bold]Status:[/bold] {result.status_code}",
        title="🌐 Browser Analysis",
        border_style="cyan"
    ))
    
    # Security headers
    if result.security_headers:
        console.print(f"\n[bold]Security Headers ({result.security_headers.get('rating', 'N/A')}):[/bold]")
        for header, info in result.security_headers.items():
            if isinstance(info, dict):
                status = "✅" if info.get("present") else "❌"
                console.print(f"  {status} {header}: {info.get('value', 'Missing')}")
    
    # Technologies
    if result.technologies:
        console.print(f"\n[bold]Technologies Detected:[/bold]")
        console.print(f"  {', '.join(result.technologies)}")
    
    # DOM Info
    console.print(f"\n[bold]DOM Analysis:[/bold]")
    console.print(f"  Forms: {result.dom_info.get('forms_count', 0)}")
    console.print(f"  Links: {result.dom_info.get('links_count', 0)}")
    console.print(f"  Scripts: {result.dom_info.get('scripts_count', 0)}")
    console.print(f"  Inputs: {result.dom_info.get('inputs', 0)}")
    
    # Forms
    if result.forms:
        console.print(f"\n[bold]Forms Found ({len(result.forms)}):[/bold]")
        for i, form in enumerate(result.forms[:5], 1):
            console.print(f"  {i}. {form.get('method', 'GET')} → {form.get('action', 'self')}")
            for inp in form.get('inputs', [])[:3]:
                console.print(f"     - {inp.get('name', 'unnamed')} ({inp.get('type', 'text')})")
    
    # Screenshot
    if result.screenshot_path:
        console.print(f"\n[bold]Screenshot:[/bold] {result.screenshot_path}")
    
    # Errors
    if result.errors:
        console.print(f"\n[yellow]Errors:[/yellow]")
        for error in result.errors:
            console.print(f"  ⚠ {error}")


# =============================================================================
# MAIN
# =============================================================================

async def main():
    """Test browser automation"""
    console.print("[bold cyan]Browser Automation Module Test[/bold cyan]\n")
    
    if not SELENIUM_AVAILABLE and not PLAYWRIGHT_AVAILABLE:
        console.print("[red]No browser engine available![/red]")
        console.print("Install: pip install selenium")
        console.print("Or: pip install playwright && playwright install")
        return
    
    console.print(f"Selenium: {'✓' if SELENIUM_AVAILABLE else '✗'}")
    console.print(f"Playwright: {'✓' if PLAYWRIGHT_AVAILABLE else '✗'}")
    
    # Test
    agent = BrowserAgent(headless=True)
    
    try:
        result = await agent.analyze_url("https://example.com")
        display_browser_result(result)
    finally:
        await agent.close()


if __name__ == "__main__":
    asyncio.run(main())
