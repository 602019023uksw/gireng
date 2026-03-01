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
from dataclasses import dataclass, field
from typing import Any, Dict, List, Set

from ghidra_agent.iana_tlds import IANA_TLDS


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

# Domain pattern: match any plausible domain, then validate TLD against IANA set
_DOMAIN_CANDIDATE_PATTERN = re.compile(
    r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+([a-zA-Z]{2,63})\b',
    re.IGNORECASE
)


# ELF section names / linker artifacts that look like domains but aren't
_ELF_SECTION_NAMES = frozenset({
    "data.rel.ro", "data.rel.ro.local", "note.gnu.build",
    "note.ABI-tag", "note.gnu.property", "init.array",
    "fini.array", "eh.frame", "eh.frame.hdr",
    "gcc.except.table", "gnu.hash", "gnu.version",
    "plt.got", "plt.sec",
})


def _is_valid_domain(match_str: str) -> bool:
    """Check if a domain candidate has a valid IANA TLD."""
    parts = match_str.rsplit('.', 1)
    if len(parts) != 2:
        return False
    tld = parts[1].lower()
    if tld not in IANA_TLDS:
        return False
    # Filter ELF section names
    name_lower = match_str.lower()
    if name_lower in _ELF_SECTION_NAMES:
        return False
    # Filter out common library filenames and ELF artifacts
    if any(name_lower.endswith(ext) for ext in ('.so', '.o', '.a', '.dylib')):
        return False
    if any(name_lower.startswith(pfx) for pfx in ('lib', 'note.', 'ld-', 'ld.')):
        return False
    if name_lower.endswith('.build') or name_lower.endswith('.property'):
        return False
    # Single-label before the dot is unlikely a real domain
    label = parts[0]
    if '.' not in label and len(label) <= 3:
        return False
    return True

EMAIL_PATTERN = re.compile(
    r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
)

# ---------------------------------------------------------------------------
# Library / system noise filters — paths, domains, emails that belong to
# statically-linked libraries (OpenSSL, zlib, etc.) or the OS, NOT malware.
# ---------------------------------------------------------------------------

# Domains that belong to libraries, not malware infrastructure
_LIBRARY_DOMAINS = frozenset({
    "openssl.org", "www.openssl.org",
    "zlib.net", "www.zlib.net",
    "gnu.org", "www.gnu.org",
    "sourceware.org",
})

# URL substrings that mark library references
_LIBRARY_URL_SUBSTRINGS = ("openssl.org", "zlib.net", "gnu.org", "sourceware.org")

# Email domains that are library noise
_LIBRARY_EMAIL_DOMAINS = ("openssl.org", "zlib.net", "gnu.org")

# File paths that are standard OS devices or library internal paths
_NOISE_UNIX_PATHS = re.compile(
    r'^(?:'
    r'/dev/(?:random|urandom|srandom|null|zero|tty|pts|ptmx|egd-pool)'
    r'|/var/run/egd-pool'
    r'|/etc/egd-pool'
    r'|/etc/entropy'
    r'|/usr/local/ssl(?:/|$)'     # OpenSSL install directory tree
    r'|/usr/lib/ssl(?:/|$)'
    r'|/etc/ssl(?:/|$)'
    r'|/etc/pki(?:/|$)'
    r')',
    re.IGNORECASE,
)

# File path patterns
UNIX_PATH_PATTERN = re.compile(
    r'/(?:bin|boot|dev|etc|home|lib|mnt|opt|proc|root|run|sbin|srv|sys|tmp|usr|var|data|opt)(?:/[^\s\x00-\x1F]+)+'
)

WINDOWS_PATH_PATTERN = re.compile(
    r'[A-Za-z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*',
    re.IGNORECASE
)

# Patterns that indicate a string is a library/OpenSSL identifier, not a mutex
_LIBRARY_MUTEX_NOISE = re.compile(
    r'(?i)'
    r'(?:^(?:id-|oid-|nid|pkcs|rsa|dsa|ecdsa|sha|aes|des|evp|ssl|tls|x509|asn1))'      # OpenSSL prefixes
    r'|(?:(?:With|Encryption|Signature|Digest|Algorithm|Certificate)$)'                    # OpenSSL suffixes
    r'|(?:^(?:NID_|OBJ_|EVP_|SSL_|BIO_|RSA_|EC_|X509_|ASN1_|PEM_|OPENSSL_|CRYPTO_))'    # OpenSSL API prefixes
    r'|(?:(?:data|text|rodata|bss|symtab|strtab|shstrtab|dynsym|dynstr|rela?\.)'           # ELF sections
    r'|(?:^[a-z]{2,6}(?:With|And)[A-Z]))'                                                 # camelCase OID-style
)

# X.509/PKI/LDAP/CMS/ASN.1 attribute-name substrings (case-insensitive).
# If a camelCase candidate contains any of these, it's almost certainly an
# OpenSSL OID long name, not a real mutex.
_PKI_SUBSTRINGS = re.compile(
    r'(?i)(?:'
    r'certificate|keyUsage|keyIdentifier|policyIdentif|constraint|'
    r'revocation|distributionPoint|authorityInfo|subjectInfo|'
    r'subjectAlt|subjectDirect|subjectDomain|issuerDomain|'
    r'issuingDistrib|encryptedContent|recipientEncrypt|unprotectedAttr|'
    r'signedContent|originatorSignature|digestAlgorithm|'
    r'encapContent|otherRevInfo|contentInfo|'
    r'pilotAttribute|pilotObject|pilotOrgan|domainRelated|'
    r'simpleSecurityObj|physicalDelivery|facsimileTelephone|'
    r'internationalISDN|registeredAddress|preferredDelivery|'
    r'presentationAddress|crossCertificate|enhancedSearchGuide|'
    r'protocolInformation|supportedAlgorithm|deltaRevocation|'
    r'anyExtendedKey|jurisdictionLocal|jurisdictionCountry|'
    r'jurisdictionState|cessationOfOp|privilegeWithdrawn|'
    r'affiliationChanged|holdInstruction|privateKeyUsage|'
    r'organizationalStatus|mailPreference|documentPublish|'
    r'documentIdentif|documentLocation|singleLevelQuality|'
    r'subtreeMinimum|subtreeMaximum|organizationName|'
    r'organizationalUnit|stateOrProvince|unstructuredName|'
    r'unstructuredAddress|challengePassword|extendedCertificate|'
    r'homePostalAddress|homeTelephone|mobileTelephone|pagerTelephone|'
    r'friendlyCountry|x500Unique|msSmartcard|inhibitAnyPolicy|'
    r'inhibitPolicyMapping|requireExplicitPolicy|'
    r'permittedSubtree|excludedSubtree|pcPathLength|'
    r'revocationReason|singleExtension|responseExtension|'
    r'generationQualifier|caseIgnoreIA5|nsCaRevocation|'
    r'businessCategory|policyMapping|basicOCSP|acceptableResponse|'
    r'targetInformation|associatedDomain|lastModifiedTime|'
    r'ripemd|WithRSA|WithDSA|WithECDSA|WithSHA|Encryption|Signature'
    r')'
)


def _is_camelcase_identifier(s: str) -> bool:
    """Return True if *s* looks like a code identifier (camelCase).

    CamelCase compound names (like X.509/LDAP attribute names, e.g.
    ``ripemd160WithRSA``) are almost never real mutex names.  We accept
    alphanumeric strings as long as they are predominantly alphabetic and
    contain at least one lower→upper transition.
    """
    if not s.isalnum():
        return False
    # Must be mostly letters (at least 70% alpha) to avoid hex/numeric IDs
    alpha_count = sum(1 for c in s if c.isalpha())
    if alpha_count < len(s) * 0.7:
        return False
    # Count word-boundary transitions (lower→upper)
    boundaries = sum(1 for i in range(1, len(s)) if s[i].isupper() and s[i - 1].islower())
    return boundaries >= 1


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
    'AES', 'RSA', 'DES', 'Blowfish', 'ChaCha', 'Salsa20',
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

        # Extract URLs — filter library references
        for url in URL_PATTERN.findall(value):
            if url not in seen_urls:
                url_lower = url.lower()
                if not any(lib in url_lower for lib in _LIBRARY_URL_SUBSTRINGS):
                    seen_urls.add(url)
                    iocs.urls.append(url)

        # Extract domains (but not IPs) — validate TLD against IANA set
        # Filter out library domains
        for m in _DOMAIN_CANDIDATE_PATTERN.finditer(value):
            domain = m.group(0)
            if (domain not in seen_domains
                    and not IP_PATTERN.match(domain)
                    and _is_valid_domain(domain)
                    and domain.lower() not in _LIBRARY_DOMAINS):
                seen_domains.add(domain)
                iocs.domains.append(domain)

        # Extract file paths — filter standard OS/library paths
        for path in UNIX_PATH_PATTERN.findall(value):
            if path not in seen_paths and len(path) > 3 and not _NOISE_UNIX_PATHS.match(path):
                seen_paths.add(path)
                iocs.file_paths.append(path)

        for path in WINDOWS_PATH_PATTERN.findall(value):
            # Require meaningful path content: at least 6 chars and a subdirectory
            if path not in seen_paths and len(path) >= 6 and '\\' in path[3:]:
                seen_paths.add(path)
                iocs.file_paths.append(path)

        # Extract emails — filter library email addresses
        for email in EMAIL_PATTERN.findall(value):
            if email not in seen_emails:
                if not any(email.lower().endswith('@' + d) for d in _LIBRARY_EMAIL_DOMAINS):
                    seen_emails.add(email)
                    iocs.emails.append(email)

        # Extract registry keys
        for reg in REGISTRY_PATTERN.findall(value):
            if reg not in seen_registry:
                seen_registry.add(reg)
                iocs.registry_keys.append(reg)

        # Extract potential mutexes/event names (long alphanumeric strings)
        # Require mixed case or special patterns to reduce false positives
        # Filter out library identifiers (OpenSSL OIDs, ELF symbol names, etc.)
        if len(value) >= 16 and value.isalnum() and not value.isdigit() and not value.islower() and not value.isupper():
            if (value not in seen_mutexes
                    and not _LIBRARY_MUTEX_NOISE.search(value)
                    and not _PKI_SUBSTRINGS.search(value)
                    and not _is_camelcase_identifier(value)):
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
    """Extract IOCs from the full agent state (Ghidra, R2, and Qiling)."""
    all_strings = []

    # Ghidra strings
    ghidra_strings = state.get("analysis_results", {}).get("strings", {})
    if ghidra_strings.get("ok"):
        all_strings.extend(ghidra_strings.get("strings", []))

    # Radare2 strings
    r2_strings = state.get("r2_analysis_results", {}).get("strings", {})
    if r2_strings.get("ok"):
        all_strings.extend(r2_strings.get("strings", []))

    # Qiling dynamic artifacts (network/syscalls/api args)
    qiling = state.get("qiling_analysis_results", {})
    if qiling:
        network = qiling.get("network_activity", {})
        if isinstance(network, dict):
            for conn in network.get("connections", []) or []:
                if isinstance(conn, dict):
                    addr = conn.get("address")
                    port = conn.get("port")
                    if addr:
                        all_strings.append({"value": f"{addr}:{port}" if port else str(addr)})
            for dns in network.get("dns_queries", []) or []:
                if isinstance(dns, dict) and dns.get("domain"):
                    all_strings.append({"value": str(dns["domain"])})
            indicators = network.get("indicators", {})
            if isinstance(indicators, dict):
                for c2 in indicators.get("c2_candidates", []) or []:
                    all_strings.append({"value": str(c2)})
                for domain in indicators.get("dns_domains", []) or []:
                    all_strings.append({"value": str(domain)})

        syscalls = qiling.get("syscalls", {})
        if isinstance(syscalls, dict):
            syscall_rows = syscalls.get("syscalls", [])
            if isinstance(syscall_rows, list):
                for call in syscall_rows:
                    if not isinstance(call, dict):
                        continue
                    all_strings.append({"value": str(call.get("name", ""))})
                    for arg in call.get("args", []) or []:
                        all_strings.append({"value": str(arg)})

        api_calls = qiling.get("api_calls", {})
        if isinstance(api_calls, dict):
            api_rows = api_calls.get("api_calls", [])
            if isinstance(api_rows, list):
                for api in api_rows:
                    if not isinstance(api, dict):
                        continue
                    all_strings.append({"value": str(api.get("name", ""))})
                    params = api.get("args", {})
                    if isinstance(params, dict):
                        for v in params.values():
                            all_strings.append({"value": str(v)})

    if not all_strings:
        return IOCs()

    return extract_iocs_from_strings(all_strings)


def _extract_llm_verdict(summary: str) -> str | None:
    """Parse the LLM summary to extract its explicit verdict.

    Returns one of: 'Malware', 'Suspicious', 'Clean', or None if not found.
    """
    if not summary:
        return None
    lower = summary.lower()

    # Look for explicit "Verdict: X" pattern (highest priority)
    import re
    verdict_match = re.search(r'\*\*verdict:\s*(malware|suspicious|clean|benign|not[_ ]?malicious|false[_ ]?positive)\*\*', lower)
    if verdict_match:
        v = verdict_match.group(1)
        if v in ('clean', 'benign', 'not malicious', 'not_malicious', 'false positive', 'false_positive'):
            return 'Clean'
        if v == 'suspicious':
            return 'Suspicious'
        return 'Malware'

    # Fallback: look for strong verdict signals in conclusion section
    # Extract the conclusion section if present
    conclusion_match = re.search(r'(?:##\s*(?:11\.?)?\s*conclusion|\bconclusion\b)(.*?)(?:##|$)', lower, re.DOTALL)
    conclusion = conclusion_match.group(1) if conclusion_match else lower[-2000:]

    # Strong benign signals
    benign_patterns = [
        r'false positive',
        r'no (?:evidence|indication|sign)s? of (?:malicious|malware)',
        r'(?:benign|legitimate|standard|unmodified) (?:binary|library|component|tool|software|program)',
        r'not (?:malicious|malware)',
        r'no malicious (?:capabilities|behavior|activity|intent|code|logic)',
        r'assessed as (?:clean|benign|not malicious|a false positive)',
        r'verdict:\s*clean',
    ]
    benign_score = sum(1 for p in benign_patterns if re.search(p, conclusion))

    # Strong malicious signals
    malicious_patterns = [
        r'(?:confirmed|identified as|classified as) (?:malware|malicious|trojan|backdoor|ransomware|rat)',
        r'c2 (?:communication|server|infrastructure|beacon)',
        r'(?:exfiltrat|steal|harvest)(?:es?|ing|ion) (?:data|credentials|information)',
        r'exploit (?:payload|code|chain)',
        r'verdict:\s*malware',
    ]
    mal_score = sum(1 for p in malicious_patterns if re.search(p, conclusion))

    if benign_score >= 2 and mal_score == 0:
        return 'Clean'
    if mal_score >= 2 and benign_score == 0:
        return 'Malware'
    if benign_score > mal_score:
        return 'Clean'
    if mal_score > benign_score:
        return 'Malware'
    return None


_QILING_RISK_POINTS = {
    "low": 4,
    "medium": 8,
    "high": 14,
    "critical": 20,
}

_QILING_HIGH_RISK_SYSCALLS = frozenset(
    {
        "ptrace",
        "process_vm_writev",
        "process_vm_readv",
        "execve",
        "clone",
        "mprotect",
        "mmap",
        "connect",
        "socket",
        "writeprocessmemory",
        "createremotethread",
        "ntcreatethreadex",
    }
)


def _score_qiling_dynamic_behavior(state: Dict[str, Any], indicators: List[str]) -> int:
    """Score Qiling runtime signals (syscalls + evasion) into verdict risk."""
    qiling = state.get("qiling_analysis_results", {})
    if not isinstance(qiling, dict) or not qiling:
        return 0

    score = 0

    # Syscall risk scoring
    syscalls = qiling.get("syscalls", {})
    if isinstance(syscalls, dict):
        syscall_rows = syscalls.get("syscalls", [])
        if not isinstance(syscall_rows, list):
            syscall_rows = []

        summary = syscalls.get("summary", {})
        suspicious_calls = summary.get("suspicious_calls", []) if isinstance(summary, dict) else []
        if isinstance(suspicious_calls, list) and suspicious_calls:
            suspicious_points = 0
            for item in suspicious_calls[:20]:
                if isinstance(item, dict):
                    risk = str(item.get("risk", "")).lower()
                    suspicious_points += _QILING_RISK_POINTS.get(risk, 6)
                else:
                    suspicious_points += 6
            score += min(35, suspicious_points)
            indicators.append(f"Qiling suspicious syscalls: {len(suspicious_calls)}")

        syscall_names = {
            str(call.get("name", "")).lower()
            for call in syscall_rows
            if isinstance(call, dict) and call.get("name")
        }
        high_risk_hits = sorted(name for name in syscall_names if name in _QILING_HIGH_RISK_SYSCALLS)
        if high_risk_hits:
            score += min(30, len(high_risk_hits) * 6)
            indicators.append(f"Qiling high-risk syscalls: {', '.join(high_risk_hits[:6])}")

    # Evasion scoring
    evasion = qiling.get("evasion_techniques", {})
    if isinstance(evasion, dict):
        evasion_payload = evasion.get("evasion_techniques", evasion)
        if isinstance(evasion_payload, dict):
            techniques = evasion_payload.get("techniques", [])
            if not isinstance(techniques, list):
                techniques = []
            summary = evasion_payload.get("summary", {})
            risk_level = str(summary.get("risk_level", "")).lower() if isinstance(summary, dict) else ""
            total = len(techniques)
            if isinstance(summary, dict):
                try:
                    total = max(total, int(summary.get("total_techniques", total)))
                except (TypeError, ValueError):
                    pass

            if total > 0 or risk_level in {"medium", "high", "critical"}:
                score += min(40, total * 10)
                score += _QILING_RISK_POINTS.get(risk_level, 0)
                indicators.append(f"Qiling evasion techniques: {total} (risk: {risk_level or 'unknown'})")

                mitre_ids = sorted(
                    {
                        str(t.get("mitre_id"))
                        for t in techniques
                        if isinstance(t, dict) and t.get("mitre_id")
                    }
                )
                if mitre_ids:
                    indicators.append(f"Qiling MITRE evasion IDs: {', '.join(mitre_ids[:6])}")

    return score


def calculate_verdict(iocs: IOCs, state: Dict[str, Any]) -> tuple:
    """Calculate malware verdict based on IOCs and analysis state.

    Returns:
        tuple: (verdict_name, verdict_class, indicators, score)
        - verdict_name: "Malicious", "Suspicious", "Potentially Unwanted", or "Clean/Unknown"
        - verdict_class: "malicious", "suspicious", "clean", or "unknown"
        - indicators: List of human-readable indicator descriptions
        - score: Numerical score for debugging
    """
    # Gather strings from both tools
    all_string_vals = []
    strings_data = state.get("analysis_results", {}).get("strings", {})
    if strings_data.get("ok"):
        all_string_vals.extend([s.get("value", "").lower() for s in strings_data.get("strings", [])])
    r2_strings_data = state.get("r2_analysis_results", {}).get("strings", {})
    if r2_strings_data.get("ok"):
        all_string_vals.extend([s.get("value", "").lower() for s in r2_strings_data.get("strings", [])])

    # Include Qiling dynamic syscall/API names in capability scoring.
    # This lets runtime-observed behavior contribute even when static strings are sparse.
    qiling_results = state.get("qiling_analysis_results", {})
    if isinstance(qiling_results, dict):
        syscalls = qiling_results.get("syscalls", {})
        if isinstance(syscalls, dict):
            syscall_rows = syscalls.get("syscalls")
            if isinstance(syscall_rows, list):
                for call in syscall_rows:
                    if not isinstance(call, dict):
                        continue
                    name = str(call.get("name", "")).lower()
                    if name:
                        all_string_vals.append(name)
                    args = call.get("args", [])
                    if isinstance(args, list):
                        all_string_vals.extend(str(arg).lower() for arg in args[:8])

        api_calls = qiling_results.get("api_calls", {})
        if isinstance(api_calls, dict):
            api_rows = api_calls.get("api_calls", [])
            if isinstance(api_rows, list):
                for api in api_rows:
                    if not isinstance(api, dict):
                        continue
                    name = str(api.get("name", "")).lower()
                    module = str(api.get("module", "")).lower()
                    if name:
                        all_string_vals.append(name)
                    if module:
                        all_string_vals.append(module)
                    args = api.get("args", {})
                    if isinstance(args, dict):
                        all_string_vals.extend(str(v).lower() for v in list(args.values())[:8])
                    elif isinstance(args, list):
                        all_string_vals.extend(str(v).lower() for v in args[:8])

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

    # Score capabilities from strings (both Ghidra + R2)
    if all_string_vals:
        strings_vals = " ".join(all_string_vals)
        if any(x in strings_vals for x in ["socket", "connect", "recv", "send"]):
            score += 20
            indicators.append("Network capability detected")
        if any(x in strings_vals for x in ["encrypt", "aes", "rsa", "cipher"]):
            score += 15
            indicators.append("Cryptographic capability detected")
        if any(x in strings_vals for x in ["exec", "system", "popen", "shell"]):
            score += 25
            indicators.append("Command execution capability detected")

    # Score Qiling runtime behavior (dynamic syscall/evasion signals)
    score += _score_qiling_dynamic_behavior(state, indicators)

    # Check if the LLM summary provides a clear verdict (expert override)
    llm_verdict = _extract_llm_verdict(state.get("summary", ""))

    if llm_verdict:
        # LLM expert analysis overrides the naive IOC heuristic
        if llm_verdict == 'Clean':
            indicators.append("LLM analysis: benign / false positive")
            return "Clean", "clean", indicators, min(score, 9)
        elif llm_verdict == 'Suspicious':
            indicators.append("LLM analysis: suspicious")
            return "Suspicious", "suspicious", indicators, max(min(score, 100), 40)
        elif llm_verdict == 'Malware':
            indicators.append("LLM analysis: confirmed malicious")
            return "Malware", "malicious", indicators, max(min(score, 100), 80)

    # Fallback: IOC-based heuristic when LLM verdict is unavailable
    capped = min(score, 100)
    if capped >= 80:
        return "Malware", "malicious", indicators, capped
    elif capped >= 40:
        return "Suspicious", "suspicious", indicators, capped
    elif capped >= 10:
        return "Suspicious", "suspicious", indicators, capped
    else:
        return "Clean", "clean", indicators, capped
