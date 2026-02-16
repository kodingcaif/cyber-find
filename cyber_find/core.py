import asyncio
import csv
import hashlib
import json
import logging
import os
import sqlite3
import time
from collections import defaultdict, deque
from datetime import date, datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

import aiohttp
import cloudscraper
import pandas as pd
import requests
import yaml
from aiohttp import ClientTimeout
from bs4 import BeautifulSoup
from fake_useragent import UserAgent

# Optional dependencies for enhanced features
try:
    import colorama
    from tqdm import tqdm

    colorama.init()
except ImportError:
    pass

logger = logging.getLogger("cyberfind")


class SearchMode(Enum):
    """Search modes for different stealth levels"""

    STANDARD = "standard"
    DEEP = "deep"
    STEALTH = "stealth"
    AGGRESSIVE = "aggressive"


class OutputFormat(Enum):
    """Output formats for results"""

    TXT = "txt"
    JSON = "json"
    CSV = "csv"
    HTML = "html"
    EXCEL = "excel"
    SQLITE = "sqlite"


class SiteCategory(Enum):
    """Categories for site classification"""

    SOCIAL_MEDIA = "social_media"
    FORUMS = "forums"
    BLOGS = "blogs"
    GAMING = "gaming"
    PROGRAMMING = "programming"
    ECOMMERCE = "ecommerce"
    RUSSIAN = "russian"
    ALL = "all"


class CyberFind:
    """Main class for CyberFind OSINT tool"""

    def __init__(self, config_path: str = "config.yaml", no_color: bool = False):
        """Initialize CyberFind with configuration"""
        self.config = self.load_config(config_path)
        self.no_color = no_color
        self.initialize_components()

    def load_config(self, config_path: str) -> Dict[str, Any]:
        """Load configuration from YAML file"""
        default_config = {
            "general": {
                "timeout": 30,
                "max_threads": 50,
                "retry_attempts": 3,
                "retry_delay": 2,
                "user_agents_rotation": True,
                "rate_limit_delay": 0.5,
            },
            "proxy": {
                "enabled": False,
                "list": [],
                "rotation": True,
            },
            "database": {
                "sqlite_path": "cyberfind.db",
            },
            "output": {
                "default_format": "json",
                "save_all_results": True,
            },
            "advanced": {
                "metadata_extraction": True,
                "cache_results": True,
                "verify_ssl": True,
            },
        }

        if os.path.exists(config_path):
            try:
                with open(config_path, "r", encoding="utf-8") as f:
                    user_config = yaml.safe_load(f) or {}

                def update_dict(d: Dict, u: Dict) -> None:
                    """Recursively update dictionary"""
                    for k, v in u.items():
                        if isinstance(v, dict) and k in d and isinstance(d[k], dict):
                            update_dict(d[k], v)
                        else:
                            d[k] = v

                update_dict(default_config, user_config)
            except Exception as e:
                logger.warning(
                    f"Error loading config file {config_path}: {e}. Using default config."
                )

        return default_config

    def get_builtin_site_path(self, list_name: str) -> Optional[Path]:
        """
        Get path to built-in site list file.
        Works both in development and after `pip install`.
        """
        filename = f"{list_name}.txt"

        # 1. Try from package resources (works after pip install)
        try:
            import importlib.resources as pkg_resources
            from pathlib import Path as _Path

            resource_path = pkg_resources.files("cyber_find.sites").joinpath(filename)
            # Check if resource exists by trying to read it
            try:
                with pkg_resources.as_file(resource_path) as rp:
                    if rp.exists():
                        return _Path(str(rp))
            except (OSError, ValueError):
                pass
        except Exception as e:
            logger.debug(f"Could not load {filename} from package: {e}")

        # 2. Try local directory (for development)
        local_path = Path(__file__).parent / "sites" / filename
        if local_path.exists():
            return local_path

        logger.error(f"Built-in site list not found: {filename}")
        return None

    def initialize_components(self) -> None:
        """Initialize all components"""
        self.ua = UserAgent()
        self.session = requests.Session()
        self.cloud_session = cloudscraper.create_scraper()

        self.proxy_list: List[str] = []
        self.current_proxy_index = 0

        self.init_database()

        # Initialize statistics
        self.stats: Dict[str, Any] = {
            "total_checks": 0,
            "found_accounts": 0,
            "errors": 0,
            "start_time": None,
            "end_time": None,
            "sites_checked": defaultdict(int),
            "response_times": deque(maxlen=10000),  # Limit to prevent memory leak
        }

        self.cache: Dict[str, Any] = {}
        self.cache_ttl = 300

        # Load built-in site lists
        self.builtin_sites = self.load_builtin_sites()

    def prepare_search_value(self, value: str, value_type: str) -> str:
        """Prepare value for URL insertion"""
        if value_type == "email":
            import hashlib

            return hashlib.md5(value.lower().encode("utf-8"), usedforsecurity=False).hexdigest()
        elif value_type == "phone":
            import re

            return re.sub(r"[^\d+]", "", value)
        else:
            return value

    async def passive_search_async(
        self, queries: List[str], engines: List[str], max_concurrent: int = 10
    ) -> Dict[str, Any]:
        """Perform passive reconnaissance using search engines"""
        import urllib.parse

        from bs4 import BeautifulSoup

        async def fetch_engine(query: str, engine: str):
            query_enc = urllib.parse.quote_plus(query)
            headers = self.generate_headers(SearchMode.STEALTH)

            url_map = {
                "google": f"https://www.google.com/search?q={query_enc}",
                "bing": f"https://www.bing.com/search?q={query_enc}",
                "wayback": f"https://web.archive.org/cdx/search/cdx?url=*{urllib.parse.quote(query.split()[-1])}*&output=json",
            }

            if engine not in url_map:
                return engine, query, []

            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(url_map[engine], headers=headers) as resp:
                        text = await resp.text()
                        urls = []

                        if engine == "wayback":
                            import json

                            try:
                                data = json.loads(text)
                                urls = [
                                    f"https://web.archive.org/web/{item[1]}/{item[2]}"
                                    for item in data[1:5]
                                ]  # top 4
                            except Exception:
                                pass
                        else:
                            soup = BeautifulSoup(text, "html.parser")
                            for a in soup.find_all("a", href=True):
                                href = str(a["href"])
                                if href.startswith("/url?q="):
                                    clean_url = href.split("/url?q=")[1].split("&")[0]
                                    if (
                                        "google.com" not in clean_url
                                        and "bing.com" not in clean_url
                                    ):
                                        urls.append(urllib.parse.unquote(clean_url))

                        return engine, query, urls
            except Exception as e:
                logger.error(f"Passive error ({engine}): {e}")
                return engine, query, []

        # Run all queries
        tasks = []
        for query in queries:
            for engine in engines:
                tasks.append(fetch_engine(query, engine))

        responses = await asyncio.gather(*tasks, return_exceptions=True)

        # Process results
        results: Dict[str, Dict[str, Any]] = {}
        for resp in responses:
            if isinstance(resp, Exception):
                continue
            engine, query, urls = resp  # type: ignore
            key = query
            if key not in results:
                results[key] = {"found": [], "errors": 0}
            results[key]["found"].extend(urls)

        # Deduplicate
        for key in results:
            results[key]["found"] = list(set(results[key]["found"]))

        return {
            "results": results,
            "statistics": {
                "total_checks": len(tasks),
                "found_accounts": sum(len(r["found"]) for r in results.values()),
                "errors": sum(1 for r in responses if isinstance(r, Exception)),
            },
        }

    def load_builtin_sites(self) -> Dict[str, List[Dict[str, Any]]]:
        """Load built-in site lists from files"""
        return {}

    def get_builtin_site_list(self, list_name: str = "quick") -> List[Dict[str, Any]]:
        """Get built-in site list by name"""
        if list_name in self.builtin_sites:
            return self.builtin_sites[list_name]
        else:
            return self.builtin_sites.get("quick", [])

    def list_builtin_categories(self) -> Dict[str, int]:
        """Show available built-in categories and site counts"""
        categories = {}
        for name, sites in self.builtin_sites.items():
            categories[name] = len(sites)
        return categories

    def init_database(self) -> None:
        """Initialize SQLite database"""
        db_path = self.config["database"]["sqlite_path"]

        if db_path:
            if not os.path.isabs(db_path):
                db_path = os.path.join(os.getcwd(), db_path)

            db_dir = os.path.dirname(db_path)
            if db_dir:
                os.makedirs(db_dir, exist_ok=True)
        else:
            db_path = os.path.join(os.getcwd(), "cyberfind.db")

        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        cursor = self.conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS search_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                site_name TEXT NOT NULL,
                url TEXT NOT NULL,
                status_code INTEGER,
                response_time REAL,
                found BOOLEAN,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                metadata TEXT,
                UNIQUE(username, site_name)
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS statistics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                date DATE NOT NULL UNIQUE,
                searches_count INTEGER DEFAULT 0,
                accounts_found INTEGER DEFAULT 0,
                total_time REAL DEFAULT 0
            )
        """)

        self.conn.commit()

    @staticmethod
    def _json_serializer(obj: Any) -> Any:
        """JSON serializer for objects not serializable by default json module"""
        if isinstance(obj, (datetime, date)):
            return obj.isoformat()
        elif hasattr(obj, "isoformat"):
            return obj.isoformat()
        elif isinstance(obj, (set, tuple)):
            return list(obj)
        elif isinstance(obj, defaultdict):
            return dict(obj)
        elif hasattr(obj, "__dict__"):
            return obj.__dict__
        raise TypeError(f"Object of type {obj.__class__.__name__} is not JSON serializable")

    async def search_async(
        self,
        usernames: Optional[List[str]] = None,
        sites_file: Optional[str] = None,
        builtin_list: Optional[str] = None,
        mode: SearchMode = SearchMode.STANDARD,
        output_format: OutputFormat = OutputFormat.JSON,
        output_file: Optional[str] = None,
        max_concurrent: int = 30,
        email: Optional[str] = None,
        phone: Optional[str] = None,
    ):
        """
        Main search method supporting username, email, and phone

        Args:
            usernames: List of usernames to search for
            sites_file: Path to file with sites list
            builtin_list: Name of built-in site list to use
            mode: Search mode (standard, deep, stealth, aggressive)
            output_format: Format for output results
            output_file: Filename to save results
            max_concurrent: Maximum concurrent requests
            email: Email address to search for (mutually exclusive with usernames/phone)
            phone: Phone number to search for (mutually exclusive with usernames/email)

        Returns:
            Dictionary with search results, report and statistics
        """

        self.stats["start_time"] = datetime.now()

        # Determine search targets and type
        if email:
            search_targets = [email]
            search_type = "email"
        elif phone:
            search_targets = [phone]
            search_type = "phone"
        elif usernames:
            search_targets = usernames
            search_type = "username"
        else:
            logger.error("No search targets provided (usernames, email, or phone)")
            return {"results": {}, "report": {}, "statistics": self.stats}

        # Load and filter sites by search type
        all_sites = await self.load_sites_async(sites_file, builtin_list)
        sites = [site for site in all_sites if site.get("value_type", "username") == search_type]

        if not sites:
            logger.error(f"No sites available for {search_type} search")
            return {"results": {}, "report": {}, "statistics": self.stats}

        print(f"📋 Loaded {len(sites)} sites for {search_type} search")

        all_results = {}

        # Search for each target
        for target in search_targets:
            print(f"\n🔍 Searching: {target} (type: {search_type})")
            user_results = await self.search_single_user_async(target, sites, mode, max_concurrent)
            all_results[target] = user_results

            # Save intermediate results if configured
            if self.config["output"]["save_all_results"]:
                self.save_results_intermediate(target, user_results)

        self.stats["end_time"] = datetime.now()

        # Save results if output file specified
        if output_file:
            await self.save_results_async(all_results, output_format, output_file)

        # Generate report and update statistics
        report = await self.generate_report_async(all_results)
        self.update_statistics()

        return {"results": all_results, "report": report, "statistics": self.stats}

    async def load_sites_async(
        self, sites_file: Optional[str] = None, builtin_list: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Load sites from file or built-in list with value type detection"""
        sites = []

        if builtin_list:
            file_path = self.get_builtin_site_path(builtin_list)
            if file_path:
                sites.extend(await self.load_sites_from_file_async(str(file_path)))
            else:
                logger.error(f"Built-in list '{builtin_list}' not found!")
                return []

        elif sites_file:
            if os.path.exists(sites_file):
                sites.extend(await self.load_sites_from_file_async(sites_file))
            else:
                logger.error(f"File not found: {sites_file}")
                return []

        else:
            file_path = self.get_builtin_site_path("quick")
            if file_path:
                sites.extend(await self.load_sites_from_file_async(str(file_path)))

        # Process sites and detect value type
        processed_sites: List[Dict[str, Any]] = []
        for site in sites:
            key = (site["name"], site["url_pattern"])
            if any(k == key for k in [(s["name"], s["url_pattern"]) for s in processed_sites]):
                continue

            # Detect value type
            url_pattern = site["url_pattern"]
            if "{email_hash}" in url_pattern:
                value_type = "email"
            elif "{phone}" in url_pattern:
                value_type = "phone"
            else:
                value_type = "username"

            processed_site = {
                "name": site.get("name", "Unknown"),
                "url_pattern": url_pattern,
                "method": site.get("method", "GET"),
                "category": site.get("category", "unknown"),
                "priority": site.get("priority", 5),
                "timeout": site.get("timeout", self.config["general"]["timeout"]),
                "retry": site.get("retry", self.config["general"]["retry_attempts"]),
                "headers": site.get("headers", {}),
                "cookies": site.get("cookies", {}),
                "requires_javascript": site.get("requires_javascript", False),
                "requires_captcha": site.get("requires_captcha", False),
                "check_strings": site.get("check_strings", []),
                "error_strings": site.get("error_strings", []),
                "valid_status_codes": site.get("valid_status_codes", [200]),
                "invalid_status_codes": site.get("invalid_status_codes", [404, 410]),
                "check_type": site.get("check_type", "content"),
                "value_type": value_type,
            }
            processed_sites.append(processed_site)

        logger.info(f"Loaded {len(processed_sites)} sites")
        return processed_sites

    async def load_sites_from_file_async(self, file_path: str) -> List[Dict[str, Any]]:
        """Load sites from file (local or remote)"""
        sites: List[Dict[str, Any]] = []
        file_path_str = str(file_path)

        try:
            if file_path_str.startswith("http"):
                async with aiohttp.ClientSession() as session:
                    async with session.get(file_path_str) as response:
                        content = await response.text()
            else:
                if not os.path.exists(file_path_str):
                    logger.warning(f"File not found: {file_path_str}")
                    return sites

                with open(file_path_str, "r", encoding="utf-8") as f:
                    content = f.read()

            # Parse each line
            for line in content.split("\n"):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                # Handle different delimiters
                if "|" in line:
                    parts = [p.strip() for p in line.split("|")]
                elif "\t" in line:
                    parts = [p.strip() for p in line.split("\t")]
                else:
                    parts = [p.strip() for p in line.split(",")]

                if len(parts) >= 2:
                    site = self.parse_site_line(parts)
                    if site:
                        sites.append(site)

        except Exception as e:
            logger.error(f"Error loading file {file_path}: {e}")

        return sites

    def parse_site_line(self, parts: List[str]) -> Optional[Dict[str, Any]]:
        """Parse a line from sites file into site dictionary"""
        try:
            if len(parts) < 2:
                return None
            name = parts[0].strip()
            url_pattern = parts[1].strip()

            # Validate URL pattern
            if not url_pattern or not self.validate_url(url_pattern.replace("{username}", "test")):
                logger.warning(f"Invalid URL pattern for {name}: {url_pattern}")
                return None

            # Ensure URL pattern has {username} placeholder
            if "{username}" not in url_pattern and "${username}" not in url_pattern:
                if url_pattern.endswith("/"):
                    url_pattern += "{username}"
                else:
                    url_pattern += "/{username}"
            site = {
                "name": name,
                "url_pattern": url_pattern,
                "method": "GET",
                "category": "unknown",
                "priority": 5,
                "timeout": self.config["general"]["timeout"],
                "retry": self.config["general"]["retry_attempts"],
                "headers": {},
                "cookies": {},
                "requires_javascript": False,
                "requires_captcha": False,
                "check_strings": [],
                "error_strings": [],
                "valid_status_codes": [200],
                "invalid_status_codes": [404, 410],
                "check_type": "status_code",
            }
            # Parse optional fields
            if len(parts) >= 3:
                category = parts[2].strip()
                if category in [cat.value for cat in SiteCategory]:
                    site["category"] = category
            if len(parts) >= 4:
                try:
                    site["priority"] = int(parts[3].strip())
                except ValueError:
                    pass
            # Parse success strings (if exists)
            if len(parts) >= 5:
                site["check_strings"] = [s.strip() for s in parts[4].split(",") if s.strip()]
            # Parse error strings (if exists)
            if len(parts) >= 6:
                site["error_strings"] = [s.strip() for s in parts[5].split(",") if s.strip()]
            return site
        except Exception as e:
            logger.error(f"Error parsing site line: {e}")
            return None

    async def search_single_user_async(
        self,
        username: str,
        sites: List[Dict[str, Any]],
        mode: SearchMode,
        max_concurrent: int,
    ) -> Dict[str, Any]:
        """Search for a single user across all sites"""

        user_results: Dict[str, Any] = {
            "username": username,
            "found": [],
            "not_found": [],
            "errors": [],
            "metadata": {},
        }

        # Sort sites by priority (higher priority first)
        sites_sorted = sorted(sites, key=lambda x: x["priority"], reverse=True)
        semaphore = asyncio.Semaphore(max_concurrent)

        print(f"  Checking {len(sites_sorted)} sites...")

        # Create tasks for all sites
        tasks = []
        for i, site in enumerate(sites_sorted):
            task = asyncio.create_task(self.check_site_async(username, site, mode, semaphore))
            tasks.append(task)

            # Show progress every 10 sites
            if i % 10 == 0 and i > 0:
                print(f"    Progress: {i}/{len(sites_sorted)}")

        # Wait for all tasks to complete
        results = await asyncio.gather(*tasks, return_exceptions=True)

        found_count = 0
        error_count = 0

        # Process results
        for i, result in enumerate(results):
            site = sites_sorted[i]
            if isinstance(result, Exception):
                user_results["errors"].append(
                    {
                        "site": site["name"],
                        "url": site["url_pattern"].replace("{username}", username),
                        "error": str(result),
                    }
                )
                self.stats["errors"] += 1
                error_count += 1
                continue

            self.stats["total_checks"] += 1

            # Cast result to dict after Exception check
            result_dict: Dict[str, Any] = result  # type: ignore
            if result_dict.get("found"):
                user_results["found"].append(result_dict)
                self.stats["found_accounts"] += 1
                found_count += 1
                # Show found accounts immediately with green color
                self.print_colored(f"    ✅ Found: {result_dict['site']}", "green")
            elif result_dict.get("error"):
                user_results["errors"].append(result_dict)
                self.stats["errors"] += 1
                error_count += 1
                # Show errors immediately with yellow color
                error_msg = result_dict.get("error", "Unknown error")
                if "rate" in error_msg.lower() or "limit" in error_msg.lower():
                    self.print_colored(f"    ⚠️  Rate-limited: {result_dict['site']}", "yellow")
                else:
                    self.print_colored(f"    ⚠️  Error: {result_dict['site']}", "yellow")
            else:
                user_results["not_found"].append(result_dict)
                # Optionally show not found with red color (commented out to reduce verbosity)
                # self.print_colored(f"    ❌ Not found: {result_dict['site']}", "red")

        print(f"  Done: {found_count} found, {error_count} errors")

        # Add metadata
        user_results["metadata"] = {
            "search_timestamp": datetime.now().isoformat(),
            "search_mode": mode.value,
            "sites_checked": len(sites),
            "accounts_found": len(user_results["found"]),
            "errors_count": len(user_results["errors"]),
        }

        return user_results

    async def check_site_async(
        self,
        username: str,
        site: Dict[str, Any],
        mode: SearchMode,
        semaphore: asyncio.Semaphore,
    ) -> Dict[str, Any]:
        """Check if user exists on a specific site"""

        async with semaphore:
            result = {
                "site": site["name"],
                "url": None,
                "found": False,
                "status_code": None,
                "response_time": 0,
                "error": None,
                "metadata": {},
            }

            try:
                url = site["url_pattern"].replace("{username}", username)
                result["url"] = url

                start_time = time.time()

                # Make request
                response_data = await self.request_standard_async(url, site, mode)

                result["response_time"] = time.time() - start_time
                try:
                    self.stats["response_times"].append(result["response_time"])
                except TypeError:
                    pass

                if response_data["success"]:
                    result["status_code"] = response_data.get("status", 200)

                    # Extract metadata if enabled
                    if self.config.get("advanced", {}).get("metadata_extraction", True):
                        metadata = await self.extract_metadata_async(
                            url, response_data.get("content", "")
                        )
                        result["metadata"].update(metadata)
                        result["metadata"]["category"] = site.get("category", "unknown")

                    # Check if user exists
                    result["found"] = self.check_user_exists(response_data, site, username)
                else:
                    result["error"] = response_data.get("error", "Unknown error")

            except Exception as e:
                result["error"] = str(e)
                logger.error(f"Error checking {site['name']}: {e}")

            return result

    async def request_standard_async(
        self, url: str, site: Dict[str, Any], mode: SearchMode
    ) -> Dict[str, Any]:
        """Make HTTP request with retries"""

        headers = self.generate_headers(mode)
        headers.update(site.get("headers", {}))

        timeout = ClientTimeout(total=site.get("timeout", self.config["general"]["timeout"]))
        max_retries = site.get("retry", self.config["general"]["retry_attempts"])

        for attempt in range(max_retries):
            try:
                async with aiohttp.ClientSession(timeout=timeout) as session:
                    async with session.get(url, headers=headers) as response:
                        content = await response.text()
                        return {
                            "success": True,
                            "status": response.status,
                            "headers": dict(response.headers),
                            "content": content,
                        }
            except asyncio.TimeoutError:
                if attempt == max_retries - 1:
                    # Extract site name from URL for better error message
                    site_name = site.get("name", url.split("/")[2] if "/" in url else "site")
                    timeout_value = site.get("timeout", self.config["general"]["timeout"])
                    return {
                        "success": False,
                        "error": f"⚠️ Request timed out for {site_name}. Try increasing timeout with `--timeout {timeout_value + 10}`.",
                    }
                await asyncio.sleep(self.config["general"]["retry_delay"])
            except Exception as e:
                if attempt == max_retries - 1:
                    return {"success": False, "error": str(e)}
                await asyncio.sleep(self.config["general"]["retry_delay"])

        return {"success": False, "error": "Max retries exceeded"}

    def generate_headers(self, mode: SearchMode) -> Dict[str, str]:
        """Generate HTTP headers based on search mode"""
        base_headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "DNT": "1",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "User-Agent": self.ua.random,
        }

        if mode == SearchMode.STEALTH:
            base_headers.update(
                {
                    "Sec-Fetch-Dest": "document",
                    "Sec-Fetch-Mode": "navigate",
                    "Sec-Fetch-Site": "none",
                    "Sec-Fetch-User": "?1",
                    "Cache-Control": "max-age=0",
                }
            )
        elif mode == SearchMode.AGGRESSIVE:
            base_headers.update(
                {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                }
            )

        return base_headers

    def check_user_exists(
        self, response_data: Dict[str, Any], site: Dict[str, Any], username: str
    ) -> bool:
        """Determine if user exists based on status code and error strings"""
        status = response_data.get("status", 0)

        # First check invalid status codes
        if status in site.get("invalid_status_codes", [404, 410]):
            return False

        # Check error strings if available
        if site.get("error_strings"):
            content_lower = response_data.get("content", "").lower()
            for err in site["error_strings"]:
                if err.lower() in content_lower:
                    return False

        # Check valid status codes
        return status in site.get("valid_status_codes", [200])

    def dns_enumeration(self, domain: str) -> Dict[str, Any]:
        """Perform DNS enumeration for a domain"""
        try:
            import dns.resolver

            results: Dict[str, Any] = {"domain": domain, "records": {}, "errors": []}

            record_types = ["A", "AAAA", "MX", "TXT", "NS", "SOA", "CNAME"]

            for record_type in record_types:
                try:
                    answers = dns.resolver.resolve(domain, record_type)
                    results["records"][record_type] = [str(rdata) for rdata in answers]
                except Exception as e:
                    results["errors"].append(f"{record_type}: {str(e)}")

            return results
        except ImportError:
            return {"error": "dns-python not installed"}
        except Exception as e:
            return {"error": str(e)}

    def whois_lookup(self, domain: str) -> Dict[str, Any]:
        """Perform WHOIS lookup for a domain"""
        try:
            import whois

            w = whois.whois(domain)
            return {
                "domain": domain,
                "registrar": w.registrar,  # type: ignore
                "creation_date": str(w.creation_date),  # type: ignore
                "expiration_date": str(w.expiration_date),  # type: ignore
                "name_servers": w.name_servers,  # type: ignore
                "emails": w.emails,  # type: ignore
                "org": w.org,  # type: ignore
                "country": w.country,  # type: ignore
            }
        except ImportError:
            return {"error": "python-whois not installed"}
        except Exception as e:
            return {"error": str(e)}

    def shodan_search(self, query: str, api_key: Optional[str] = None) -> Dict[str, Any]:
        """Search Shodan for IP/domain information"""
        if not api_key:
            return {"error": "Shodan API key required"}
        try:
            import shodan

            assert api_key is not None  # for mypy
            api = shodan.Shodan(api_key)
            results = api.search(query)
            return {
                "query": query,
                "total": results["total"],
                "matches": results["matches"][:10],  # First 10 results
            }
        except ImportError:
            return {"error": "shodan not installed"}
        except Exception as e:
            return {"error": str(e)}

    def virustotal_scan(self, url: str, api_key: Optional[str] = None) -> Dict[str, Any]:
        """Scan URL with VirusTotal"""
        if not api_key:
            return {"error": "VirusTotal API key required"}
        try:
            import vt

            assert api_key is not None  # for mypy
            client = vt.Client(api_key)
            url_id = vt.url_id(url)
            url_obj = client.get_object(f"/urls/{url_id}")
            return {
                "url": url,
                "malicious": url_obj.last_analysis_stats["malicious"],
                "suspicious": url_obj.last_analysis_stats["suspicious"],
                "harmless": url_obj.last_analysis_stats["harmless"],
                "undetected": url_obj.last_analysis_stats["undetected"],
            }
        except ImportError:
            return {"error": "virustotal-api not installed"}
        except Exception as e:
            return {"error": str(e)}

    def wayback_machine_search(self, url: str, limit: int = 10) -> Dict[str, Any]:
        """Search Wayback Machine for historical snapshots"""
        try:
            import waybackpy

            wayback = waybackpy.Url(url)
            snapshots = wayback.get(limit)

            results = []
            for snapshot in snapshots:
                results.append(
                    {
                        "url": snapshot.archive_url,
                        "timestamp": snapshot.timestamp,
                        "status": snapshot.status_code,
                    }
                )

            return {"original_url": url, "snapshots": results}
        except ImportError:
            return {"error": "waybackpy not installed"}
        except Exception as e:
            return {"error": str(e)}

    async def selenium_scrape_async(self, url: str, wait_time: int = 5) -> Dict[str, Any]:
        """Scrape JavaScript-heavy sites using Selenium"""
        try:
            from selenium import webdriver
            from selenium.webdriver.chrome.options import Options
            from selenium.webdriver.common.by import By
            from selenium.webdriver.support import expected_conditions as EC
            from selenium.webdriver.support.ui import WebDriverWait

            options = Options()
            options.add_argument("--headless")
            options.add_argument("--no-sandbox")
            options.add_argument("--disable-dev-shm-usage")

            driver = webdriver.Chrome(options=options)
            driver.get(url)

            # Wait for page to load
            WebDriverWait(driver, wait_time).until(
                EC.presence_of_element_located((By.TAG_NAME, "body"))
            )

            content = driver.page_source
            title = driver.title

            driver.quit()

            return {
                "url": url,
                "title": title,
                "content": content[:50000],  # Limit content size
            }
        except ImportError:
            return {"error": "selenium not installed"}
        except Exception as e:
            return {"error": str(e)}

    def validate_url(self, url: str) -> bool:
        """Validate URL format"""
        try:
            import validators

            result = validators.url(url)
            return bool(result) if result else False
        except ImportError:
            # Fallback validation
            import re

            url_pattern = re.compile(
                r"^https?://"  # http:// or https://
                r"(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|"  # domain...
                r"localhost|"  # localhost...
                r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"  # ...or ip
                r"(?::\d+)?"  # optional port
                r"(?:/?|[/?]\S+)$",
                re.IGNORECASE,
            )
            return url_pattern.match(url) is not None

    def create_progress_bar(self, total: int, desc: str = "Progress") -> Any:
        """Create a progress bar"""
        try:
            from tqdm import tqdm

            return tqdm(total=total, desc=desc, unit="item")
        except ImportError:
            # Fallback: simple print
            class FakeTqdm:
                def __init__(self, total, desc, unit):
                    self.total = total
                    self.desc = desc
                    self.current = 0

                def update(self, n=1):
                    self.current += n
                    print(f"{self.desc}: {self.current}/{self.total}")

                def close(self):
                    pass

            return FakeTqdm(total, desc, "item")

    def print_colored(self, text: str, color: str = "white") -> None:
        """Print colored text (respects no_color flag)"""
        if self.no_color:
            print(text)
            return

        try:
            import colorama

            colors = {
                "red": colorama.Fore.RED,
                "green": colorama.Fore.GREEN,
                "yellow": colorama.Fore.YELLOW,
                "blue": colorama.Fore.BLUE,
                "magenta": colorama.Fore.MAGENTA,
                "cyan": colorama.Fore.CYAN,
                "white": colorama.Fore.WHITE,
                "reset": colorama.Fore.RESET,
            }
            print(f"{colors.get(color, colors['white'])}{text}{colors['reset']}")
        except ImportError:
            print(text)

    async def advanced_search_async(
        self,
        username: str,
        enable_dns: bool = False,
        enable_whois: bool = False,
        enable_shodan: bool = False,
        enable_vt: bool = False,
        enable_wayback: bool = False,
        api_keys: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """Perform advanced OSINT search with multiple tools"""
        results = {"username": username, "basic_search": {}, "advanced_features": {}}

        # Basic username search
        basic_results = await self.search_async(usernames=[username])
        results["basic_search"] = basic_results

        # Advanced features
        if enable_dns and username.count(".") >= 1:
            results["advanced_features"]["dns"] = self.dns_enumeration(username)  # type: ignore

        if enable_whois and username.count(".") >= 1:
            results["advanced_features"]["whois"] = self.whois_lookup(username)  # type: ignore

        if enable_shodan and api_keys and "shodan" in api_keys:
            results["advanced_features"]["shodan"] = self.shodan_search(  # type: ignore
                username, api_keys["shodan"]
            )

        if enable_vt and api_keys and "virustotal" in api_keys:
            # Check found URLs with VT
            vt_results = []
            for user_results in basic_results["results"].values():
                for account in user_results["found"]:
                    if "url" in account:
                        vt_result = self.virustotal_scan(account["url"], api_keys["virustotal"])
                        vt_results.append({"url": account["url"], "vt_result": vt_result})
            results["advanced_features"]["virustotal"] = vt_results  # type: ignore

        if enable_wayback:
            # Check Wayback for found URLs
            wayback_results = []
            for user_results in basic_results["results"].values():
                for account in user_results["found"]:
                    if "url" in account:
                        wb_result = self.wayback_machine_search(account["url"], limit=5)
                        wayback_results.append({"url": account["url"], "wayback": wb_result})
            results["advanced_features"]["wayback"] = wayback_results  # type: ignore

        return results

    def generate_advanced_report(self, results: Dict[str, Any]) -> str:
        """Generate advanced OSINT report"""
        report = []
        report.append("=" * 80)
        report.append("CYBERFIND ADVANCED OSINT REPORT")
        report.append("=" * 80)
        report.append(f"Target: {results['username']}")
        report.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append("")

        # Basic search summary
        basic = results.get("basic_search", {})
        if "statistics" in basic:
            stats = basic["statistics"]
            report.append("BASIC SEARCH RESULTS:")
            report.append(f"  Total checks: {stats.get('total_checks', 0)}")
            report.append(f"  Accounts found: {stats.get('found_accounts', 0)}")
            report.append(f"  Errors: {stats.get('errors', 0)}")
            report.append("")

        # Advanced features
        advanced = results.get("advanced_features", {})

        if "dns" in advanced and "error" not in advanced["dns"]:
            report.append("DNS RECORDS:")
            dns_data = advanced["dns"]
            for record_type, records in dns_data.get("records", {}).items():
                report.append(f"  {record_type}: {', '.join(records)}")
            report.append("")

        if "whois" in advanced and "error" not in advanced["whois"]:
            report.append("WHOIS INFORMATION:")
            whois_data = advanced["whois"]
            report.append(f"  Registrar: {whois_data.get('registrar', 'N/A')}")
            report.append(f"  Creation Date: {whois_data.get('creation_date', 'N/A')}")
            report.append(f"  Expiration Date: {whois_data.get('expiration_date', 'N/A')}")
            report.append(f"  Country: {whois_data.get('country', 'N/A')}")
            report.append("")

        if "shodan" in advanced and "error" not in advanced["shodan"]:
            report.append("SHODAN RESULTS:")
            shodan_data = advanced["shodan"]
            report.append(f"  Total matches: {shodan_data.get('total', 0)}")
            for match in shodan_data.get("matches", [])[:3]:
                report.append(
                    f"  IP: {match.get('ip_str', 'N/A')} | Port: {match.get('port', 'N/A')}"
                )
            report.append("")

        if "virustotal" in advanced:
            report.append("VIRUSTOTAL ANALYSIS:")
            for vt_result in advanced["virustotal"]:
                vt = vt_result.get("vt_result", {})
                if "error" not in vt:
                    report.append(f"  URL: {vt_result['url']}")
                    report.append(
                        f"    Malicious: {vt.get('malicious', 0)} | Suspicious: {vt.get('suspicious', 0)}"
                    )
            report.append("")

        if "wayback" in advanced:
            report.append("WAYBACK MACHINE:")
            for wb_result in advanced["wayback"]:
                wb = wb_result.get("wayback", {})
                if "error" not in wb:
                    snapshots = wb.get("snapshots", [])
                    report.append(f"  URL: {wb_result['url']} | Snapshots: {len(snapshots)}")
            report.append("")

        report.append("=" * 80)
        return "\n".join(report)

    async def extract_metadata_async(self, url: str, content: str) -> Dict[str, Any]:
        """Extract metadata from HTML content"""
        metadata = {
            "title": "",
            "description": "",
            "keywords": [],
            "links": [],
            "images": [],
        }

        try:
            soup = BeautifulSoup(content, "html.parser")

            # Extract title
            title_tag = soup.find("title")
            if title_tag:
                metadata["title"] = title_tag.text.strip()

            # Extract meta tags
            for meta in soup.find_all("meta"):
                name = str(meta.get("name", "")).lower()  # type: ignore
                content_val = str(meta.get("content", ""))  # type: ignore
                if name == "description":
                    metadata["description"] = content_val
                elif name == "keywords":
                    metadata["keywords"] = [k.strip() for k in content_val.split(",")]

            # Extract links
            for link in soup.find_all("a", href=True):
                href = str(link["href"])
                if href.startswith("http"):  # type: ignore
                    metadata["links"].append(href)  # type: ignore

            # Extract images
            for img in soup.find_all("img", src=True):
                metadata["images"].append(img["src"])  # type: ignore

        except Exception as e:
            logger.debug(f"Error extracting metadata: {e}")

        return metadata

    def save_results_intermediate(self, username: str, results: Dict[str, Any]) -> None:
        """Save intermediate results to database"""
        try:
            cursor = self.conn.cursor()
            for result in results["found"] + results["not_found"] + results["errors"]:
                cursor.execute(
                    """
                    INSERT OR REPLACE INTO search_results
                    (username, site_name, url, status_code, response_time, found, metadata)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        username,
                        result["site"],
                        result.get("url", ""),
                        result.get("status_code"),
                        result.get("response_time", 0),
                        result.get("found", False),
                        json.dumps(result.get("metadata", {}), default=self._json_serializer),
                    ),
                )
            self.conn.commit()
        except Exception as e:
            logger.error(f"Error saving to database: {e}")

    async def save_results_async(
        self, all_results: Dict[str, Any], output_format: OutputFormat, output_file: str
    ) -> None:
        """Save results in specified format"""

        output_path = Path(output_file)

        if output_format == OutputFormat.JSON:
            await self.save_as_json_async(all_results, output_path)
        elif output_format == OutputFormat.CSV:
            await self.save_as_csv_async(all_results, output_path)
        elif output_format == OutputFormat.HTML:
            await self.save_as_html_async(all_results, output_path)
        elif output_format == OutputFormat.EXCEL:
            await self.save_as_excel_async(all_results, output_path)
        elif output_format == OutputFormat.SQLITE:
            self.save_to_database(all_results)

    async def save_as_json_async(self, results: Dict[str, Any], output_path: Path) -> None:
        """Save results as JSON"""
        try:

            def convert_for_json(obj: Any) -> Any:
                """Convert objects for JSON serialization"""
                if isinstance(obj, (datetime, date)):
                    return obj.isoformat()
                elif isinstance(obj, (set, tuple)):
                    return list(obj)
                elif isinstance(obj, defaultdict):
                    return dict(obj)
                elif isinstance(obj, dict):
                    return {k: convert_for_json(v) for k, v in obj.items()}
                elif isinstance(obj, (list, tuple)):
                    return [convert_for_json(item) for item in obj]
                elif hasattr(obj, "__dict__"):
                    return convert_for_json(obj.__dict__)
                else:
                    return obj

            stats_copy = convert_for_json(self.stats)

            full_results = {
                "metadata": {
                    "generated_at": datetime.now().isoformat(),
                    "tool": "CyberFind",
                    "version": "0.1.0",
                    "statistics": stats_copy,
                },
                "results": convert_for_json(results),
            }

            with open(f"{output_path}.json", "w", encoding="utf-8") as f:
                json.dump(
                    full_results,
                    f,
                    indent=2,
                    ensure_ascii=False,
                    default=self._json_serializer,
                )
            logger.info(f"Results saved to {output_path}.json")
        except Exception as e:
            logger.error(f"Error saving JSON: {e}")

    async def save_as_csv_async(self, results: Dict[str, Any], output_path: Path) -> None:
        """Save results as CSV"""
        try:
            with open(f"{output_path}.csv", "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(
                    [
                        "Username",
                        "Site",
                        "URL",
                        "Status Code",
                        "Response Time",
                        "Found",
                        "Error",
                        "Title",
                    ]
                )

                for username, user_results in results.items():
                    for result in (
                        user_results["found"] + user_results["not_found"] + user_results["errors"]
                    ):
                        metadata = result.get("metadata", {})
                        # Ensure all values are properly serialized for CSV
                        response_time = result.get("response_time", 0)
                        if not isinstance(response_time, (int, float)):
                            response_time = 0

                        writer.writerow(
                            [
                                str(username),
                                str(result.get("site", "")),
                                str(result.get("url", "")),
                                str(result.get("status_code", "")),
                                float(response_time),
                                str(result.get("found", False)),
                                str(result.get("error", "")),
                                str(metadata.get("title", "")),
                            ]
                        )
            logger.info(f"Results saved to {output_path}.csv")
        except Exception as e:
            logger.error(f"Error saving CSV: {e}")

    async def save_as_html_async(self, results: Dict[str, Any], output_path: Path) -> None:
        """Save results as HTML report"""
        try:
            found_count = sum(len(r["found"]) for r in results.values())
            not_found_count = sum(len(r["not_found"]) for r in results.values())
            errors_count = sum(len(r["errors"]) for r in results.values())

            start_time = self.stats.get("start_time", datetime.now())
            end_time = self.stats.get("end_time", datetime.now())
            time_taken = (end_time - start_time).total_seconds()

            users_html_parts = []
            for username, user_results in results.items():
                rows = []
                for result in user_results["found"]:
                    rows.append(f"""
                    <tr>
                        <td>{result['site']}</td>
                        <td><a href="{result.get('url', '#')}" target="_blank">{result.get('url', '')}</a></td>
                        <td>{result.get('status_code', '')}</td>
                        <td>{result.get('response_time', 0):.2f}s</td>
                    </tr>
                    """)
                user_table = "".join(rows)
                users_html_parts.append(f"""
                <div class="user-section">
                    <h3>User: {username}</h3>
                    <table class="results-table">
                        <thead>
                            <tr><th>Site</th><th>URL</th><th>Status</th><th>Time</th></tr>
                        </thead>
                        <tbody>
                            {user_table}
                        </tbody>
                    </table>
                </div>
                """)

            all_users_html = "".join(users_html_parts)

            html_content = f"""
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>CyberFind Report</title>
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 20px; }}
                    .summary {{ background-color: #f0f0f0; padding: 10px; margin-bottom: 20px; }}
                    table.results-table {{ border-collapse: collapse; width: 100%; margin-bottom: 20px; }}
                    th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                    th {{ background-color: #4CAF50; color: white; }}
                </style>
            </head>
            <body>
                <h1>CyberFind Report</h1>
                <div class="summary">
                    <p><strong>Generated:</strong> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
                    <p><strong>Accounts found:</strong> {found_count}</p>
                    <p><strong>Not found:</strong> {not_found_count}</p>
                    <p><strong>Errors:</strong> {errors_count}</p>
                    <p><strong>Time taken:</strong> {time_taken:.2f} seconds</p>
                </div>
                {all_users_html}
            </body>
            </html>
            """
            with open(f"{output_path}.html", "w", encoding="utf-8") as f:
                f.write(html_content)
            logger.info(f"Results saved to {output_path}.html")
        except Exception as e:
            logger.error(f"Error saving HTML: {e}")

    async def save_as_excel_async(self, results: Dict[str, Any], output_path: Path) -> None:
        """Save results as Excel file"""
        try:
            with pd.ExcelWriter(f"{output_path}.xlsx", engine="openpyxl") as writer:
                data = []
                for username, user_results in results.items():
                    for result in user_results["found"]:
                        data.append(
                            {
                                "Username": username,
                                "Site": result["site"],
                                "URL": result.get("url", ""),
                                "Status": "Found",
                                "Status Code": result.get("status_code", ""),
                                "Response Time": result.get("response_time", 0),
                                "Title": result.get("metadata", {}).get("title", ""),
                            }
                        )
                df = pd.DataFrame(data)
                df.to_excel(writer, sheet_name="Results", index=False)

                stats_df = pd.DataFrame([self.stats])
                stats_df.to_excel(writer, sheet_name="Statistics", index=False)

            logger.info(f"Results saved to {output_path}.xlsx")
        except Exception as e:
            logger.error(f"Error saving Excel: {e}")

    @staticmethod
    def normalize_value(value: str, value_type: str) -> Optional[str]:
        if not value:
            return None

        if value_type == "email":
            # MD5 used for lookup/normalization, not for cryptographic security
            return hashlib.md5(value.lower().encode("utf-8"), usedforsecurity=False).hexdigest()
        elif value_type == "phone":
            normalized = "".join(ch for ch in value if ch.isdigit())
            return normalized
        return None

    def save_to_database(self, results: Dict[str, Any]) -> None:
        """Save results to SQLite database"""
        try:
            cursor = self.conn.cursor()
            for username, user_results in results.items():
                for result in (
                    user_results["found"] + user_results["not_found"] + user_results["errors"]
                ):
                    cursor.execute(
                        """
                        INSERT OR REPLACE INTO search_results
                        (username, site_name, url, status_code, response_time, found, metadata)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                        (
                            username,
                            result["site"],
                            result.get("url", ""),
                            result.get("status_code"),
                            result.get("response_time", 0),
                            result.get("found", False),
                            json.dumps(
                                result.get("metadata", {}),
                                default=self._json_serializer,
                            ),
                        ),
                    )
            self.conn.commit()
            logger.info("Results saved to database")
        except Exception as e:
            logger.error(f"Error saving to database: {e}")

    async def generate_report_async(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive search report"""
        report: Dict[str, Any] = {
            "summary": {
                "total_users": len(results),
                "total_accounts_found": 0,
                "total_errors": 0,
                "unique_sites_found": set(),
                "categories_found": defaultdict(int),
            },
            "users": {},
            "risk_assessment": {},
            "recommendations": [],
        }

        for username, user_results in results.items():
            user_summary: Dict[str, Any] = {
                "accounts_found": len(user_results["found"]),
                "sites_found": [],
                "categories": defaultdict(int),
            }

            for result in user_results["found"]:
                site_name = result["site"]
                user_summary["sites_found"].append(site_name)  # type: ignore
                report["summary"]["unique_sites_found"].add(site_name)

                category = result.get("metadata", {}).get("category", "unknown")
                user_summary["categories"][category] += 1  # type: ignore
                report["summary"]["categories_found"][category] += 1  # type: ignore

            report["summary"]["total_accounts_found"] += user_summary["accounts_found"]
            report["summary"]["total_errors"] += len(user_results["errors"])
            report["users"][username] = user_summary

        report["risk_assessment"] = self.assess_risks(results)
        report["recommendations"] = self.generate_recommendations(results)

        return report

    def assess_risks(self, results: Dict[str, Any]) -> Dict[str, str]:
        """Assess privacy and security risks based on found accounts"""
        risks = {
            "privacy_risk": "low",
            "reputation_risk": "low",
            "security_risk": "low",
            "social_engineering_risk": "low",
            "overall_risk": "low",
        }

        high_risk_sites = {"linkedin", "facebook", "instagram", "twitter", "vk", "ok"}
        medium_risk_sites = {"github", "gitlab", "reddit", "pinterest", "telegram"}

        found_sites = set()
        for user_results in results.values():
            for result in user_results["found"]:
                found_sites.add(result["site"].lower())

        high_risk_count = len(found_sites.intersection(high_risk_sites))
        medium_risk_count = len(found_sites.intersection(medium_risk_sites))

        if high_risk_count >= 3:
            risks["privacy_risk"] = "high"
            risks["overall_risk"] = "high"
        elif high_risk_count >= 1 or medium_risk_count >= 3:
            risks["privacy_risk"] = "medium"
            risks["overall_risk"] = "medium"

        total_accounts = sum(len(r["found"]) for r in results.values())
        if total_accounts > 10:
            risks["reputation_risk"] = "medium"

        return risks

    def generate_recommendations(self, results: Dict[str, Any]) -> List[str]:
        """Generate recommendations based on search results"""
        recommendations = []
        total_accounts = sum(len(r["found"]) for r in results.values())

        if total_accounts == 0:
            recommendations.append("User not found on popular platforms")
        elif total_accounts < 3:
            recommendations.append("Few accounts found, possible use of pseudonym")
        else:
            recommendations.append("Many accounts found, check privacy settings")

        has_linkedin = False
        has_vk = False
        for user_results in results.values():
            for result in user_results["found"]:
                if "linkedin" in result["site"].lower():
                    has_linkedin = True
                if "vk" in result["site"].lower():
                    has_vk = True

        if has_linkedin:
            recommendations.append("LinkedIn profile found - check contacts and connections")
        else:
            recommendations.append("LinkedIn profile not found - user may use different name")

        if has_vk:
            recommendations.append("VK profile found - Russian-speaking user identified")

        return recommendations

    def update_statistics(self) -> None:
        """Update statistics in database"""
        try:
            cursor = self.conn.cursor()
            start_time = self.stats.get("start_time", datetime.now())
            end_time = self.stats.get("end_time", datetime.now())
            today = datetime.now().date().isoformat()

            if isinstance(start_time, datetime) and isinstance(end_time, datetime):
                total_time = (end_time - start_time).total_seconds()
            else:
                total_time = 0

            cursor.execute(
                """
                SELECT id FROM statistics WHERE date = ?
            """,
                (today,),
            )

            existing = cursor.fetchone()

            if existing:
                cursor.execute(
                    """
                    UPDATE statistics
                    SET searches_count = searches_count + ?,
                        accounts_found = accounts_found + ?,
                        total_time = total_time + ?
                    WHERE date = ?
                """,
                    (1, self.stats.get("found_accounts", 0), total_time, today),
                )
            else:
                cursor.execute(
                    """
                    INSERT INTO statistics (date, searches_count, accounts_found, total_time)
                    VALUES (?, ?, ?, ?)
                """,
                    (today, 1, self.stats.get("found_accounts", 0), total_time),
                )

            self.conn.commit()
        except Exception as e:
            logger.error(f"Error updating statistics: {e}")

    def close(self) -> None:
        """Close connections and clean up resources"""
        try:
            if hasattr(self, "conn"):
                self.conn.close()
            if hasattr(self, "session"):
                self.session.close()
        except Exception as e:
            logger.error(f"Error closing resources: {e}")

    def __del__(self) -> None:
        """Destructor to ensure resources are closed"""
        self.close()


def gravatar_hash(email: str) -> str:
    """Convert email to MD5 hash for gravatar-style lookups"""
    # MD5 used for non-security purpose (gravatar lookup)
    return hashlib.md5(email.lower().encode("utf-8"), usedforsecurity=False).hexdigest()
