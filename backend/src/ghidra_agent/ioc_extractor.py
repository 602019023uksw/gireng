"""I6: IOC (Indicators of Compromise) Extractor

Extracts IOCs from binary analysis results including:
- IP addresses and ports
- URLs and domains
- File paths
- Email addresses
- Cryptographic hashes (MD5, SHA1, SHA256)
- Registry keys (Windows)
- Mutex/event names
- C2 indicators
"""

import re
from typing import Dict, List, Any, Set
from dataclasses import dataclass, field


@dataclass
class IOCs:
    ips: List[str] = field(default_factory=list)
    urls: List[str] = field(default_factory=list)
    domains: List[str] = field(default_factory=list)
    file_paths: List[str] = field(default_factory=list)
    emails: List[str] = field(default_factory=list)
    registry_keys: List[str] = field(default_factory=list)
    mutexes: List[str] = field(default_factory=list)
    crypto_materials: List[str] = field(default_factory=list)
    suspicious_strings: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, List[str]]:
        return {
            "ips": self.ips,
            "urls": self.urls,
            "domains": self.domains,
            "file_paths": self.file_paths,
            "emails": self.emails,
            "registry_keys": self.registry_keys,
            "mutexes": self.mutexes,
            "crypto_materials": self.crypto_materials,
            "suspicious_strings": self.suspicious_strings,
        }
    
    def is_empty(self) -> bool:
        return all(len(v) == 0 for v in self.to_dict().values())


# Regex patterns for IOC extraction
IP_PATTERN = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?::\d{1,5})?\b'
)

URL_PATTERN = re.compile(
    r'https?://[^\s\x00-\x1F\"<>\'\(\)\[\]\{\}]+',
    re.IGNORECASE
)

DOMAIN_PATTERN = re.compile(
    r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:[a-zA-Z]{2,}|local|lan|home|corp)\b',
    re.IGNORECASE
)

EMAIL_PATTERN = re.compile(
    r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
)

# File path patterns
UNIX_PATH_PATTERN = re.compile(
    r'/(?:bin|boot|dev|etc|home|lib|mnt|opt|proc|root|run|sbin|srv|sys|tmp|usr|var|data|opt)(?:/[^\s\x00-\x1F]+)+'
)

WINDOWS_PATH_PATTERN = re.compile(
    r'[A-Za-z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*',
    re.IGNORECASE
)

# Windows Registry patterns
REGISTRY_PATTERN = re.compile(
    r'HKEY_[A-Z_]+\\(?:[^\s\x00-\x1F]+)',
    re.IGNORECASE
)

# Mutex/Event name patterns (common malware indicators)
MUTEX_PATTERN = re.compile(
    r'(?:Global\\|Local\\|Session\\)?[A-Za-z0-9_\-]{10,}',
    re.IGNORECASE
)

# Cryptographic hash patterns (hex strings of specific lengths)
MD5_PATTERN = re.compile(r'\b[a-fA-F0-9]{32}\b')
SHA1_PATTERN = re.compile(r'\b[a-fA-F0-9]{40}\b')
SHA256_PATTERN = re.compile(r'\b[a-fA-F0-9]{64}\b')

# Suspicious keywords that indicate malware behavior
SUSPICIOUS_KEYWORDS = [
    # C2 / Network
    'backdoor', 'c2', 'command', 'control', 'botnet', 'irc.', 'ddos',
    # Persistence
    'autorun', 'startup', 'registry', 'schedule', 'task', 'cron',
    # Stealth
    'rootkit', 'hidden', 'stealth', 'invisible', 'inject',
    # Data theft
    'password', 'credential', 'wallet', 'bitcoin', 'crypto',
    # Anti-analysis
    'debugger', 'vmware', 'virtualbox', 'sandbox', 'analysis',
    # Privilege escalation
    'exploit', 'privilege', 'elevation', 'uac', 'bypass',
]

# Crypto-related patterns
CRYPTO_KEYWORDS = [
    'AES', 'RSA', 'DES', ' Blowfish', 'ChaCha', 'Salsa20',
    'private', 'public', 'key', 'encrypt', 'decrypt', 'cipher',
    'openssl', 'libcrypto', 'EVP_', 'AES_', 'RSA_',
]


def extract_iocs_from_strings(strings_list: List[Dict[str, Any]]) -> IOCs:
    """Extract IOCs from a list of string objects."""
    iocs = IOCs()
    
    seen_ips: Set[str] = set()
    seen_urls: Set[str] = set()
    seen_domains: Set[str] = set()
    seen_paths: Set[str] = set()
    seen_emails: Set[str] = set()
    seen_registry: Set[str] = set()
    seen_mutexes: Set[str] = set()
    seen_crypto: Set[str] = set()
    seen_suspicious: Set[str] = set()
    
    for string_obj in strings_list:
        value = string_obj.get("value", "")
        if not value:
            continue
        
        # Extract IPs
        for ip in IP_PATTERN.findall(value):
            if ip not in seen_ips:
                seen_ips.add(ip)
                iocs.ips.append(ip)
        
        # Extract URLs
        for url in URL_PATTERN.findall(value):
            if url not in seen_urls:
                seen_urls.add(url)
                iocs.urls.append(url)
        
        # Extract domains (but not IPs)
        for domain in DOMAIN_PATTERN.findall(value):
            if domain not in seen_domains and not IP_PATTERN.match(domain):
                seen_domains.add(domain)
                iocs.domains.append(domain)
        
        # Extract file paths
        for path in UNIX_PATH_PATTERN.findall(value):
            if path not in seen_paths and len(path) > 3:
                seen_paths.add(path)
                iocs.file_paths.append(path)
        
        for path in WINDOWS_PATH_PATTERN.findall(value):
            if path not in seen_paths and len(path) > 3:
                seen_paths.add(path)
                iocs.file_paths.append(path)
        
        # Extract emails
        for email in EMAIL_PATTERN.findall(value):
            if email not in seen_emails:
                seen_emails.add(email)
                iocs.emails.append(email)
        
        # Extract registry keys
        for reg in REGISTRY_PATTERN.findall(value):
            if reg not in seen_registry:
                seen_registry.add(reg)
                iocs.registry_keys.append(reg)
        
        # Extract potential mutexes/event names (long alphanumeric strings)
        if len(value) >= 10 and value.isalnum():
            if value not in seen_mutexes:
                seen_mutexes.add(value)
                iocs.mutexes.append(value)
        
        # Extract cryptographic materials
        if any(kw.lower() in value.lower() for kw in CRYPTO_KEYWORDS):
            # Look for hex strings that might be keys
            for hex_str in MD5_PATTERN.findall(value):
                if hex_str not in seen_crypto:
                    seen_crypto.add(hex_str)
                    iocs.crypto_materials.append(f"Possible key/hash: {hex_str}")
            for hex_str in SHA1_PATTERN.findall(value):
                if hex_str not in seen_crypto:
                    seen_crypto.add(hex_str)
                    iocs.crypto_materials.append(f"Possible key/hash: {hex_str}")
            for hex_str in SHA256_PATTERN.findall(value):
                if hex_str not in seen_crypto:
                    seen_crypto.add(hex_str)
                    iocs.crypto_materials.append(f"Possible key/hash: {hex_str}")
        
        # Extract suspicious strings
        lower_val = value.lower()
        for keyword in SUSPICIOUS_KEYWORDS:
            if keyword in lower_val and value not in seen_suspicious:
                seen_suspicious.add(value)
                iocs.suspicious_strings.append(value)
                break
    
    return iocs


def format_iocs_for_report(iocs: IOCs) -> str:
    """Format IOCs for HTML/text report."""
    lines = []
    
    if iocs.ips:
        lines.append("IP Addresses & Ports:")
        for ip in iocs.ips[:20]:  # Limit to 20
            lines.append(f"  - {ip}")
        if len(iocs.ips) > 20:
            lines.append(f"  ... and {len(iocs.ips) - 20} more")
        lines.append("")
    
    if iocs.domains:
        lines.append("Domains:")
        for domain in iocs.domains[:15]:
            lines.append(f"  - {domain}")
        lines.append("")
    
    if iocs.urls:
        lines.append("URLs:")
        for url in iocs.urls[:10]:
            lines.append(f"  - {url}")
        lines.append("")
    
    if iocs.file_paths:
        lines.append("File Paths:")
        for path in iocs.file_paths[:15]:
            lines.append(f"  - {path}")
        lines.append("")
    
    if iocs.emails:
        lines.append("Email Addresses:")
        for email in iocs.emails:
            lines.append(f"  - {email}")
        lines.append("")
    
    if iocs.registry_keys:
        lines.append("Windows Registry Keys:")
        for reg in iocs.registry_keys[:10]:
            lines.append(f"  - {reg}")
        lines.append("")
    
    if iocs.mutexes:
        lines.append("Potential Mutex/Event Names:")
        for mutex in iocs.mutexes[:10]:
            lines.append(f"  - {mutex}")
        lines.append("")
    
    if iocs.crypto_materials:
        lines.append("Cryptographic Materials:")
        for crypto in iocs.crypto_materials[:10]:
            lines.append(f"  - {crypto}")
        lines.append("")
    
    if iocs.suspicious_strings:
        lines.append("Suspicious Indicators:")
        for susp in iocs.suspicious_strings[:15]:
            lines.append(f"  - {susp}")
        lines.append("")
    
    if not lines:
        return "No IOCs extracted."
    
    return "\n".join(lines)


def extract_iocs_from_state(state: Dict[str, Any]) -> IOCs:
    """Extract IOCs from the full agent state."""
    strings_data = state.get("analysis_results", {}).get("strings", {})
    if not strings_data.get("ok"):
        return IOCs()
    
    return extract_iocs_from_strings(strings_data.get("strings", []))


def calculate_verdict(iocs: IOCs, state: Dict[str, Any]) -> tuple:
    """Calculate malware verdict based on IOCs and analysis state.
    
    Returns:
        tuple: (verdict_name, verdict_class, indicators, score)
        - verdict_name: "Malicious", "Suspicious", "Potentially Unwanted", or "Clean/Unknown"
        - verdict_class: "malicious", "suspicious", "clean", or "unknown"
        - indicators: List of human-readable indicator descriptions
        - score: Numerical score for debugging
    """
    strings_data = state.get("analysis_results", {}).get("strings", {})
    
    score = 0
    indicators = []
    
    # Score IOCs
    if iocs.ips:
        score += len(iocs.ips) * 10
        indicators.append(f"{len(iocs.ips)} IP addresses/ports found")
    if iocs.domains:
        score += len(iocs.domains) * 5
        indicators.append(f"{len(iocs.domains)} domains found")
    if iocs.urls:
        score += len(iocs.urls) * 10
    if iocs.file_paths:
        suspicious_paths = [p for p in iocs.file_paths if any(x in p for x in ['/etc/', '/proc/', 'system32', 'startup'])]
        if suspicious_paths:
            score += len(suspicious_paths) * 15
            indicators.append(f"{len(suspicious_paths)} suspicious file paths")
    if iocs.registry_keys:
        score += len(iocs.registry_keys) * 10
        indicators.append(f"{len(iocs.registry_keys)} registry keys (persistence)")
    if iocs.mutexes:
        score += min(len(iocs.mutexes), 5) * 5
    if iocs.suspicious_strings:
        score += min(len(iocs.suspicious_strings), 10) * 5
        indicators.append(f"{len(iocs.suspicious_strings)} suspicious keywords")
    
    # Score capabilities from strings
    if strings_data.get("ok"):
        strings_vals = " ".join([s.get("value", "").lower() for s in strings_data.get("strings", [])])
        if any(x in strings_vals for x in ["socket", "connect", "recv", "send"]):
            score += 20
            indicators.append("Network capability detected")
        if any(x in strings_vals for x in ["encrypt", "aes", "rsa", "cipher"]):
            score += 15
            indicators.append("Cryptographic capability detected")
        if any(x in strings_vals for x in ["exec", "system", "popen", "shell"]):
            score += 25
            indicators.append("Command execution capability detected")
    
    # Determine verdict
    if score >= 80:
        return "Malicious", "malicious", indicators, score
    elif score >= 40:
        return "Suspicious", "suspicious", indicators, score
    elif score >= 10:
        return "Potentially Unwanted", "suspicious", indicators, score
    else:
        return "Clean/Unknown", "clean", indicators, score
