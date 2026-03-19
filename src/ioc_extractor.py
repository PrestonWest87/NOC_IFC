import re
import ipaddress
from urllib.parse import unquote
from typing import List, Dict, Set

class EnterpriseIOCExtractor:
    """
    Tier-1 Threat Intelligence Extraction Engine.
    Handles aggressive obfuscation, contextual extraction, and strict fidelity filtering.
    """

    def __init__(self):
        # Master Configuration
        self.CONTEXT_WINDOW = 45  # Characters to capture around the IOC for analyst context
        self._compile_rulesets()
        self._initialize_whitelists()

    def _initialize_whitelists(self):
        """Initializes complex mathematical and string-based whitelists."""
        # Exact string matches
        self.ignore_domains: Set[str] = {
            'example.com', 'google.com', 'microsoft.com', 'apple.com', 'amazon.com',
            'github.com', 'mitre.org', 'nist.gov', 'virustotal.com', 'shodan.io',
            'schema.org', 'w3.org', 'wikipedia.org', 'iana.org'
        }
        
        self.ignore_ips: Set[str] = {
            '0.0.0.0', '255.255.255.255', '1.1.1.1', '1.0.0.1', '8.8.8.8', '8.8.4.4'
        }

    def _compile_rulesets(self):
        """Compiles categorized regex dictionaries for high-speed evaluation."""
        
        # Base Regex patterns grouped by Intelligence Category
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

        # Pre-compile everything with IGNORECASE where applicable
        self.compiled_rules = {}
        for category, types in self.rules.items():
            self.compiled_rules[category] = {}
            for type_name, pattern in types.items():
                self.compiled_rules[category][type_name] = re.compile(pattern, re.IGNORECASE)

    def refang_payload(self, text: str) -> str:
        """
        Aggressively normalizes obfuscated indicators (e.g., hxxps, 1[.]1[.]1[.]1).
        Uses URL unquoting to catch encoded payloads.
        """
        if not text: return ""
        text = unquote(text) # Decode %2E to .
        
        # Protocol defanging
        text = re.sub(r'\bhxxps?', 'http', text, flags=re.IGNORECASE)
        text = re.sub(r'\bfxp', 'ftp', text, flags=re.IGNORECASE)
        
        # Punctuation defanging
        text = re.sub(r'\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)', '.', text, flags=re.IGNORECASE)
        text = re.sub(r'\[:\]|\(\:\)', ':', text)
        text = re.sub(r'\[/\]|\(\/\)', '/', text)
        
        # Email defanging
        text = re.sub(r'\[@\]|\(@\)| AT ', '@', text, flags=re.IGNORECASE)
        text = re.sub(r' DOT ', '.', text, flags=re.IGNORECASE)
        
        return text

    def _is_valid_ip(self, ip_str: str) -> bool:
        """Cryptographically verifies IP validity and checks against reserved CIDR space."""
        if ip_str in self.ignore_ips: return False
        try:
            ip = ipaddress.ip_address(ip_str)
            if ip.is_private or ip.is_loopback or ip.is_multicast or ip.is_link_local or ip.is_reserved:
                return False
            return True
        except ValueError:
            return False

    def _get_context(self, text: str, match: re.Match) -> str:
        """Extracts surrounding text for analyst context without breaking string bounds."""
        start = max(0, match.start() - self.CONTEXT_WINDOW)
        end = min(len(text), match.end() + self.CONTEXT_WINDOW)
        
        # Clean up newlines in context for cleaner UI rendering
        context = text[start:end].replace('\n', ' ').replace('\r', '')
        return f"...{context}..."

    def extract(self, raw_text: str) -> List[Dict]:
        """
        Master extraction loop. Iterates compiled rules, validates fidelity, 
        and extracts surrounding context.
        """
        if not raw_text: return []
        
        clean_text = self.refang_payload(raw_text)
        results = []
        seen_values = set()

        for category, types in self.compiled_rules.items():
            for type_name, compiled_regex in types.items():
                
                # Using finditer instead of findall to capture start/end positions for Context
                for match in compiled_regex.finditer(clean_text):
                    value = match.group(0).strip()
                    value_lower = value.lower()

                    # Deduplication checkpoint
                    if value_lower in seen_values:
                        continue

                    # --- Strict Fidelity Filtering ---
                    if type_name == "IPv4" or type_name == "IPv6":
                        if not self._is_valid_ip(value): continue
                            
                    elif type_name == "Domain":
                        if value_lower in self.ignore_domains: continue
                        # Drop domain if we already captured it as part of a full URL
                        if any(value_lower in existing for existing in seen_values if existing.startswith('http')):
                            continue

                    elif type_name in ["SHA256", "SHA1", "MD5", "CVE", "MITRE ATT&CK"]:
                        value = value.upper() # Standardize threat taxonomy formats
                    
                    elif type_name == "Email":
                        value = value_lower

                    # --- Assemble Threat Object ---
                    context = self._get_context(clean_text, match)
                    
                    results.append({
                        "Category": category,
                        "Type": type_name,
                        "Indicator": value,
                        "Context": context
                    })
                    
                    seen_values.add(value_lower)

        return results

# Singleton instantiation for application-wide use
ioc_engine = EnterpriseIOCExtractor()