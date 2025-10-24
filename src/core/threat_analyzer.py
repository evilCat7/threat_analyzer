import requests
from bs4 import BeautifulSoup
import urllib.parse
import colorama
import re
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict, Set
from datetime import datetime
import sqlite3

class ThreatAnalyzer():
    def __init__(self, target_url: str, max_depth: int = 3):
        """
        Initialize the security scanner with a target URL and maximum crawl depth.

        Args:
            target_url: The base URL to scan
            max_depth: Maximum depth for crawling links (default: 3)
        """
        self.target_url = target_url
        self.max_depth = max_depth 
        self.visited_urls: Set[str] = set()
        self.vulnerabilities: List[Dict] = []
        self.report_id = None # Empty until initialized in scan
        self.session = requests.Session()

        # Initialize colorama for cross-platform colored output
        colorama.init()

    def normalize_url(self, url: str) -> str:
        """Normalize the URL to prevent duplicate checks"""
        parsed = urllib.parse.urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    
    def crawl(self, url: str, depth: int = 0) -> None:
        """
        Crawl the website to discover pages and endpoints.

        Args:
            url: Current URL to crawl
            depth: Current depth in the crawl tree
        """
        if depth > self.max_depth or url in self.visited_urls:
            return

        try:
            self.visited_urls.add(url)
            response = self.session.get(url, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')

            # Find all links in the page
            links = soup.find_all('a', href=True)
            for link in links:
                next_url = urllib.parse.urljoin(url, link['href'])
                if next_url.startswith(self.target_url):
                    self.crawl(next_url, depth + 1)

        except Exception as e:
            print(f"Error crawling {url}: {str(e)}")

    def check_sql_injection(self, url: str) -> None:
        """Test for potential SQL injection vulnerabilities"""
        sql_payloads = ["'", "1' OR '1'='1", "' OR 1=1--", "' UNION SELECT NULL--"]

        for payload in sql_payloads:
            try:
                # Test GET parameters
                parsed = urllib.parse.urlparse(url)
                params = urllib.parse.parse_qs(parsed.query)

                for param in params:
                    test_url = url.replace(f"{param}={params[param][0]}", 
                                        f"{param}={payload}")
                    response = self.session.get(test_url)

                    # Look for SQL error messages
                    if any(error in response.text.lower() for error in 
                        ['sql', 'mysql', 'sqlite', 'postgresql', 'oracle']):
                        self.report_vulnerability({
                            'type': 'SQL Injection',
                            'url': url,
                            'parameter': param,
                            'payload': payload
                        })

            except Exception as e:
                print(f"Error testing SQL injection on {url}: {str(e)}")

    def check_xss(self, url: str) -> None:
        """Test for potential Cross-Site Scripting vulnerabilities"""
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')"
        ]

        for payload in xss_payloads:
            try:
                # Test GET parameters
                parsed = urllib.parse.urlparse(url)
                params = urllib.parse.parse_qs(parsed.query)

                for param in params:
                    test_url = url.replace(f"{param}={params[param][0]}", 
                                        f"{param}={urllib.parse.quote(payload)}")
                    response = self.session.get(test_url)

                    if payload in response.text:
                        self.report_vulnerability({
                            'type': 'Cross-Site Scripting (XSS)',
                            'url': url,
                            'parameter': param,
                            'payload': payload
                        })

            except Exception as e:
                print(f"Error testing XSS on {url}: {str(e)}")
    
    def check_forms(self, url: str) -> None:
        """Enhanced form testing with better error detection"""
        try:
            response = self.session.get(url)
            soup = BeautifulSoup(response.text, "html.parser")
            forms = soup.find_all("form")
            
            for form in forms:
                action = form.get("action") or ""
                method = form.get("method", "get").lower()
                form_url = urllib.parse.urljoin(url, action)
                
                # Collect input fields
                inputs = form.find_all("input")
                form_data = {}
                for inp in inputs:
                    if inp.get("name") and inp.get("type") != "submit":
                        form_data[inp.get("name")] = "test"
                
                if not form_data:
                    continue
                
                print(f"Testing form at {form_url} with method {method.upper()}")
                
                # Enhanced SQL Injection payloads
                sql_payloads = [
                    "'", 
                    "1' OR '1'='1", 
                    "' OR 1=1--", 
                    "' UNION SELECT NULL--",
                    "\" OR \"1\"=\"1",
                    "' OR 'x'='x",
                    "1'; WAITFOR DELAY '00:00:05'--"
                ]
                
                for payload in sql_payloads:
                    for name in form_data:
                        test_data = form_data.copy()
                        test_data[name] = payload
                        
                        try:
                            if method == "post":
                                r = self.session.post(form_url, data=test_data)
                            else:
                                r = self.session.get(form_url, params=test_data)
                            
                            # Enhanced error detection
                            error_indicators = [
                                'sql', 'mysql', 'sqlite', 'postgresql', 'oracle',
                                'syntax error', 'database error', 'query failed',
                                'sqlite3.', 'operational error', 'programming error',
                                'integrity error', 'constraint failed', 'database is locked',
                                'no such table', 'cannot operate on', 'SQL syntax'
                            ]
                            
                            
                            if any(err in r.text.lower() for err in error_indicators):
                                self.report_vulnerability({
                                    "type": "SQL Injection",
                                    "url": form_url,
                                    "parameter": name,
                                    "payload": payload,
                                })
                                
                        except Exception as e:
                            print(f"Error testing payload {payload}: {str(e)}")
                
                # XSS Testing
                xss_payloads = [
                    "<script>alert('XSS')</script>",
                    "<img src=x onerror=alert('XSS')>",
                    "javascript:alert('XSS')",
                    "<svg onload=alert('XSS')>"
                ]
                
                for payload in xss_payloads:
                    for name in form_data:
                        test_data = form_data.copy()
                        test_data[name] = payload
                        
                        try:
                            if method == "post":
                                r = self.session.post(form_url, data=test_data)
                            else:
                                r = self.session.get(form_url, params=test_data)
                            
                            if payload.lower() in r.text.lower():
                                self.report_vulnerability({
                                    "type": "Cross-Site Scripting (XSS)",
                                    "url": form_url,
                                    "parameter": name,
                                    "payload": payload,
                                })
                        except Exception as e:
                            print(f"Error testing XSS payload {payload}: {str(e)}")
                            
        except Exception as e:
            print(f"Error checking forms on {url}: {str(e)}")
    
    def check_sensitive_info(self, url: str) -> None:
        """Check for exposed sensitive information"""
        sensitive_patterns = {
            'email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            'phone': r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
            'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
            'api_key': r'api[_-]?key[_-]?([\'"|`])([a-zA-Z0-9]{32,45})\1'
        }

        try:
            response = self.session.get(url)

            for info_type, pattern in sensitive_patterns.items():
                matches = re.finditer(pattern, response.text)
                for match in matches:
                    self.report_vulnerability({
                        'type': 'Sensitive Information Exposure',
                        'url': url,
                        'info_type': info_type,
                        'pattern': pattern,
                        'match': match.group(0) 
                    })

        except Exception as e:
            print(f"Error checking sensitive information on {url}: {str(e)}")

    def scan(self) -> List[Dict]:
        """
        Main scanning method that coordinates the security checks

        Returns:
            List of discovered vulnerabilities
        """
        print(f"\n{colorama.Fore.BLUE}Starting security scan of {self.target_url}{colorama.Style.RESET_ALL}\n")

        # Adding report scan to the database
        with sqlite3.connect("vulns.db") as conn:
            
            try:
                cursor = conn.cursor()
                formatted_timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                cursor.execute("INSERT INTO reports(url, timestamp) VALUES (?, ?);", (self.target_url, formatted_timestamp))
                
                self.report_id = cursor.lastrowid
                conn.commit()

            except Exception as e:
                print("Error trying to connect to database...")
                print(f"Error: {e}")

        # First, crawl the website
        self.crawl(self.target_url)

        # Then run security checks on all discovered URLs
        with ThreadPoolExecutor(max_workers=5) as executor:
            for url in self.visited_urls:
                executor.submit(self.check_sql_injection, url)
                executor.submit(self.check_xss, url)
                executor.submit(self.check_sensitive_info, url)
                executor.submit(self.check_forms, url)


        return self.vulnerabilities

    def report_vulnerability(self, vulnerability: Dict) -> None:
        """Record and display found vulnerabilities"""
        self.vulnerabilities.append(vulnerability)

        print(f"{colorama.Fore.RED}[VULNERABILITY FOUND]{colorama.Style.RESET_ALL}")
        for key, value in vulnerability.items():
            print(f"{key}: {value}")
        print()

        # Saving in the database
        with sqlite3.connect("vulns.db") as conn:
            try:
                conn.execute("PRAGMA foreign_keys = ON;")
                cursor = conn.cursor()
                vuln_type = vulnerability.get("type")
                report_id = self.report_id
                if vuln_type == "SQL Injection":
                    description = f"parameter: {vulnerability.get("parameter")}, payload: {vulnerability.get("payload")}"
                    cursor.execute(
                        "INSERT INTO vulns(type, description, report_id) VALUES (?, ?, ?);",
                        (vuln_type, description, report_id)
                    )
                elif vuln_type == "Cross-Site Scripting (XSS)":
                    description = f"parameter: {vulnerability.get("parameter")}, payload: {vulnerability.get("payload")}"
                    cursor.execute(
                        "INSERT INTO vulns(type, description, report_id) VALUES (?, ?, ?);",
                        (vuln_type, description, report_id)
                    )
                elif vuln_type == "Sensitive Information Exposure":
                    description = f"info_type: {vulnerability.get("info_type")}, pattern: {vulnerability.get("pattern")}, match: {vulnerability.get("match")}"
                    cursor.execute(
                        "INSERT INTO vulns(type, description, report_id) VALUES (?, ?, ?);",
                        (vuln_type, description, report_id)
                    )

            except Exception as e:
                print("Error trying to connect to database...")
                print(f"Error: {e}")
            
                
                


