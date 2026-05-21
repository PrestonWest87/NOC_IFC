import re
import ipaddress
from urllib.parse import unquote
from typing import List, Dict, Set

class EnterpriseIOCExtractor:
    def __init__(self):
        self.CONTEXT_WINDOW = 45
        self._compile_rulesets()
        self._initialize_whitelists()

    def _initialize_whitelists(self):
        self.ignore_domains: Set[str] = {
            'example.com', 'google.com', 'microsoft.com', 'apple.com', 'amazon.com',
            'github.com', 'mitre.org', 'nist.gov', 'virustotal.com', 'shodan.io',
            'schema.org', 'w3.org', 'wikipedia.org', 'iana.org'
        }

        self.ignore_ips: Set[str] = {
            '0.0.0.0', '255.255.255.255', '1.1.1.1', '1.0.0.1', '8.8.8.8', '8.8.4.4'
        }

    def _compile_rulesets(self):
        self.rules = {
            "Network": {
                "IPv4": r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
                "IPv6": r'\b(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}\b',
                "URL": r'(?:https?|ftp|tcp|udp|ldaps?):\/\/[\w/\-?=%.]+\.[\w/\-&?=%.]+',
                "Domain": r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|info|biz|co|us|uk|ru|cn|gov|edu|mil|int|dev|ai|app|xyz)\b',
                "Email": r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
                "ASN": r'\bAS\d{3,6}\b'
            },
            "Host Artifacts": {
                "SHA256": r'\b[A-Fa-f0-9]{64}\b',
                "SHA1": r'\b[A-Fa-f0-9]{40}\b',
                "MD5": r'\b[A-Fa-f0-9]{32}\b',
                "Registry Key": r'\b(?:HKLM|HKCU|HKCR|HKU|HKCC|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)\\[a-zA-Z0-9_\\]+\b',
                "Windows Path": r'\b[A-Za-z]:\\[a-zA-Z0-9_\\\-.\s]+\b',
                "Linux Path": r'\b/(?:bin|etc|var|usr|tmp|opt|home|root)(?:/[a-zA-Z0-9_.-]+)+\b'
            },
            "Actor Infrastructure": {
                "BTC Wallet": r'\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\b',
                "XMR Wallet": r'\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b',
                "Discord C2": r'(?:discord\.com/api/webhooks/|discordapp\.com/api/webhooks/)[\w-]+/[\w-]+',
                "Telegram C2": r'(?:api\.telegram\.org/bot)[\w:-]+'
            },
            "Cloud & DevOps": {
                "AWS API Key": r'\bAKIA[0-9A-Z]{16}\b',
                "AWS S3 Bucket": r'\b[a-z0-9.-]+\.s3(?:-[a-z0-9-]+)?\.amazonaws\.com\b',
                "Azure Blob": r'\b[a-z0-9]+\.blob\.core\.windows\.net\b'
            },
            "Taxonomy": {
                "CVE": r'\bCVE-\d{4}-\d{4,7}\b',
                "MITRE ATT&CK": r'\bT\d{4}(?:\.\d{3})?\b'
            }
        }

        self.compiled_rules = {}
        for category, types in self.rules.items():
            self.compiled_rules[category] = {}
            for type_name, pattern in types.items():
                self.compiled_rules[category][type_name] = re.compile(pattern, re.IGNORECASE)

    def refang_payload(self, text: str) -> str:
        if not text: return ""
        text = unquote(text)

        text = re.sub(r'\bhxxps?', 'http', text, flags=re.IGNORECASE)
        text = re.sub(r'\bfxp', 'ftp', text, flags=re.IGNORECASE)

        text = re.sub(r'\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)', '.', text, flags=re.IGNORECASE)
        text = re.sub(r'\[:\]|\(\:\)', ':', text)
        text = re.sub(r'\[/\]|\(\/\)', '/', text)

        text = re.sub(r'\[@\]|\(@\)| AT ', '@', text, flags=re.IGNORECASE)
        text = re.sub(r' DOT ', '.', text, flags=re.IGNORECASE)

        return text

    def _is_valid_ip(self, ip_str: str) -> bool:
        if ip_str in self.ignore_ips: return False
        try:
            ip = ipaddress.ip_address(ip_str)
            if ip.is_private or ip.is_loopback or ip.is_multicast or ip.is_link_local or ip.is_reserved:
                return False
            return True
        except ValueError:
            return False

    def _get_context(self, text: str, match: re.Match) -> str:
        start = max(0, match.start() - self.CONTEXT_WINDOW)
        end = min(len(text), match.end() + self.CONTEXT_WINDOW)

        context = text[start:end].replace('\n', ' ').replace('\r', '')
        return f"...{context}..."

    def extract(self, raw_text: str) -> List[Dict]:
        if not raw_text: return []

        clean_text = self.refang_payload(raw_text)
        results = []
        seen_values = set()

        for category, types in self.compiled_rules.items():
            for type_name, compiled_regex in types.items():

                for match in compiled_regex.finditer(clean_text):
                    value = match.group(0).strip()
                    value_lower = value.lower()

                    if value_lower in seen_values:
                        continue

                    if type_name == "IPv4" or type_name == "IPv6":
                        if not self._is_valid_ip(value): continue

                    elif type_name == "Domain":
                        if value_lower in self.ignore_domains: continue
                        if any(value_lower in existing for existing in seen_values if existing.startswith('http')):
                            continue

                    elif type_name in ["SHA256", "SHA1", "MD5", "CVE", "MITRE ATT&CK"]:
                        value = value.upper()

                    elif type_name == "Email":
                        value = value_lower

                    context = self._get_context(clean_text, match)

                    results.append({
                        "Category": category,
                        "Type": type_name,
                        "Indicator": value,
                        "Context": context
                    })

                    seen_values.add(value_lower)

        return results

ioc_engine = EnterpriseIOCExtractor()
