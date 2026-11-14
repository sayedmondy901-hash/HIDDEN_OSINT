import asyncio
import aiohttp
import re
import random
import json
import os
from typing import Set, List, Dict

class ProxyManager:
    """يسحب البروكسيات المجانية، يفحصها بالتوازي، ويدير تدوير الـ IP"""
    def __init__(self):
        self.working_proxies: List[str] = []
        self.proxy_sources = [
            "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
            "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=5000&country=all"
        ]
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0"
        ]

    async def fetch_raw_proxies(self, session: aiohttp.ClientSession) -> Set[str]:
        raw_proxies = set()
        for url in self.proxy_sources:
            try:
                async with session.get(url, timeout=10) as resp:
                    if resp.status == 200:
                        text = await resp.text()
                        for line in text.splitlines():
                            line = line.strip()
                            if line and ":" in line:
                                raw_proxies.add(f"http://{line}")
            except Exception:
                pass
        return raw_proxies

    async def validate_proxy(self, session: aiohttp.ClientSession, proxy: str, sem: asyncio.Semaphore):
        """يختبر البروكسي على موقع خفيف للتأكد أنه شغال وسريع"""
        test_url = "http://httpbin.org/ip"
        async with sem:
            try:
                async with session.get(test_url, proxy=proxy, timeout=4) as resp:
                    if resp.status == 200:
                        self.working_proxies.append(proxy)
            except Exception:
                pass

    async def initialize_proxies(self, max_to_test: int = 150, target_working: int = 15):
        """تهيئة وفحص قائمة البروكسيات قبل بدء الفحص"""
        print("[*] Fetching and validating free proxies...")
        sem = asyncio.Semaphore(50)
        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(connector=connector) as session:
            all_proxies = list(await self.fetch_raw_proxies(session))
            random.shuffle(all_proxies)
            subset = all_proxies[:max_to_test]
            
            tasks = [self.validate_proxy(session, p, sem) for p in subset]
            await asyncio.gather(*tasks)

        print(f"[+] Proxy Pool Ready: {len(self.working_proxies)} fast working proxies found.")

    def get_proxy(self) -> str:
        return random.choice(self.working_proxies) if self.working_proxies else None

    def get_headers(self, extra_headers: dict = None) -> dict:
        headers = {
            "User-Agent": random.choice(self.user_agents),
            "Accept": "application/json, text/html, */*"
        }
        if extra_headers:
            headers.update(extra_headers)
        return headers


class KeyRing:
    """مسؤول عن تحميل وتدوير مفاتيح الـ API (Key Rotation)"""
    def __init__(self, config_path: str = "config.json"):
        self.keys: Dict[str, List[str]] = {}
        if os.path.exists(config_path):
            try:
                with open(config_path, "r") as f:
                    data = json.load(f)
                    # الاحتفاظ فقط بالمفاتيح الحقيقية واستبعاد النصوص الافتراضية
                    for service, k_list in data.items():
                        valid = [k for k in k_list if k and not k.startswith("PUT_YOUR_")]
                        if valid:
                            self.keys[service] = valid
            except Exception as e:
                print(f"[!] Error reading {config_path}: {e}")

    def get_key(self, service: str) -> str:
        service_keys = self.keys.get(service, [])
        return random.choice(service_keys) if service_keys else None


class AdvancedOSINTEngine:
    def __init__(self, target_domain: str, concurrency_limit: int = 10, use_proxies: bool = True):
        self.target = target_domain.lower().strip()
        self.use_proxies = use_proxies
        self.proxy_manager = ProxyManager()
        self.keyring = KeyRing()
        self.semaphore = asyncio.Semaphore(concurrency_limit)
        self.discovered_subdomains: Set[str] = set()

        escaped_domain = re.escape(self.target)
        self.subdomain_regex = re.compile(
            rf'(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{{0,61}}[a-zA-Z0-9])?\.)+{escaped_domain}'
        )

    def build_sources(self) -> List[Dict]:
        """بناء قائمة المصادر العامة + مصادر الـ API في حال توفر المفاتيح"""
        sources = [
            {"name": "crt.sh", "url": f"https://crt.sh/?q=%25.{self.target}&output=json", "headers": {}},
            {"name": "HackerTarget", "url": f"https://api.hackertarget.com/hostsearch/?q={self.target}", "headers": {}},
            {"name": "WaybackMachine", "url": f"https://web.archive.org/cdx/search/cdx?url=*.{self.target}/*&output=text&fl=original&collapse=urlkey", "headers": {}},
            {"name": "AlienVault OTX", "url": f"https://otx.alienvault.com/api/v1/indicators/domain/{self.target}/passive_dns", "headers": {}},
            {"name": "AnubisDB", "url": f"https://jldc.me/anubis/subdomains/{self.target}", "headers": {}},
            {"name": "URLScan.io", "url": f"https://urlscan.io/api/v1/search/?q=domain:{self.target}", "headers": {}}
        ]

        # إضافة VirusTotal إذا كان المفتاح موجوداً في config.json
        vt_key = self.keyring.get_key("virustotal")
        if vt_key:
            sources.append({
                "name": "VirusTotal API",
                "url": f"https://www.virustotal.com/api/v3/domains/{self.target}/subdomains?limit=40",
                "headers": {"x-apikey": vt_key}
            })

        # إضافة SecurityTrails إذا كان المفتاح موجوداً
        st_key = self.keyring.get_key("securitytrails")
        if st_key:
            sources.append({
                "name": "SecurityTrails API",
                "url": f"https://api.securitytrails.com/v1/domain/{self.target}/subdomains",
                "headers": {"APIKEY": st_key}
            })

        # إضافة Shodan إذا كان المفتاح موجوداً
        shodan_key = self.keyring.get_key("shodan")
        if shodan_key:
            sources.append({
                "name": "Shodan DNS API",
                "url": f"https://api.shodan.io/dns/domain/{self.target}?key={shodan_key}",
                "headers": {}
            })

        return sources

    async def fetch_with_retry(self, session: aiohttp.ClientSession, source: Dict, retries: int = 3) -> str:
        url = source["url"]
        name = source["name"]
        
        for attempt in range(retries):
            # في المحاولة الأخيرة، نستخدم الاتصال المباشر كخطة بديلة إذا فشل البروكسي
            proxy = self.proxy_manager.get_proxy() if (self.use_proxies and attempt < retries - 1) else None
            headers = self.proxy_manager.get_headers(source.get("headers"))

            try:
                async with self.semaphore:
                    await asyncio.sleep(random.uniform(0.3, 1.2))
                    async with session.get(url, headers=headers, proxy=proxy, timeout=20) as response:
                        if response.status == 200:
                            print(f"[+] Successfully fetched data from: {name}")
                            return await response.text()
                        elif response.status == 429:
                            wait = (2 ** attempt) + random.uniform(0.5, 1.5)
                            print(f"[!] Rate limit (429) on {name}. Switching IP & retrying in {wait:.1f}s...")
                            await asyncio.sleep(wait)
                        else:
                            print(f"[-] {name} returned HTTP {response.status}")
                            return ""
            except Exception:
                # إذا سقط البروكسي المجاني، يجرب بروكسي غيره في المحاولة التالية
                await asyncio.sleep(0.5)

        print(f"[!] Failed to retrieve data from {name} after {retries} attempts.")
        return ""

    def extract_subdomains(self, raw_text: str):
        if not raw_text:
            return
        matches = self.subdomain_regex.findall(raw_text)
        for sub in matches:
            clean_sub = sub.lower().strip()
            if not clean_sub.startswith('*') and clean_sub != self.target:
                self.discovered_subdomains.add(clean_sub)

    async def worker(self, session: aiohttp.ClientSession, source: Dict):
        raw_data = await self.fetch_with_retry(session, source)
        self.extract_subdomains(raw_data)

    async def run(self) -> List[str]:
        if self.use_proxies:
            await self.proxy_manager.initialize_proxies()

        sources = self.build_sources()
        print(f"[*] Querying {len(sources)} intelligence sources concurrently...\n" + "-"*50)

        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(connector=connector) as session:
            tasks = [self.worker(session, src) for src in sources]
            await asyncio.gather(*tasks)

        return sorted(list(self.discovered_subdomains))


if __name__ == "__main__":
    target_domain = "example.com"
    
    # يمكنك جعل use_proxies=False لو أردت تجربة السرعة القصوى بالـ IP الأساسي أولاً
    engine = AdvancedOSINTEngine(target_domain=target_domain, concurrency_limit=10, use_proxies=True)
    results = asyncio.run(engine.run())

    print("-" * 50)
    print(f"[+] Total Unique Subdomains Found for {target_domain}: {len(results)}")
    for item in results:
        print(f"  -> {item}")