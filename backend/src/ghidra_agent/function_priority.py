"""Function prioritization utilities.

Ranks functions by a composite score that combines:
    - Normalized xref count and size (structural signals)
    - Boost for functions calling security-relevant APIs (behavioral signal)
    - Boost for functions referencing suspicious strings (contextual signal)
    - Penalty for known library functions in statically-linked binaries

Formula:
    score = alpha * norm(xrefs) + beta * norm(size)
            + caller_boost + string_ref_boost - library_penalty
"""

from __future__ import annotations

import re
from typing import Any, Dict, FrozenSet, Iterable, List, Optional, Set, Tuple

# ---------------------------------------------------------------------------
# Known library function name patterns — demoted in statically-linked binaries
# ---------------------------------------------------------------------------
LIBRARY_NAME_PATTERNS: List[re.Pattern[str]] = [
    # OpenSSL / BoringSSL
    re.compile(r"^(SSL|ssl|TLS|tls|DTLS|dtls)\d?_", re.IGNORECASE),
    re.compile(r"^(X509|ASN1|BIO|BN|RSA|DSA|EC|EVP|PEM|PKCS|CMS|OCSP|HMAC|DH)", re.IGNORECASE),
    re.compile(r"^(SHA\d|MD5|AES|SEED|RC4|DES|CAMELLIA|aesni|vpaes|bsaes|gcm_)", re.IGNORECASE),
    re.compile(r"^(d2i_|i2d_|OBJ_|OPENSSL_|CRYPTO_|ERR_|sk_|lh_)", re.IGNORECASE),
    re.compile(r"_it$", re.IGNORECASE),  # ASN.1 item tables like X509_ALGOR_it
    # zlib
    re.compile(r"^(inflate|deflate|compress|uncompress|adler32|crc32)", re.IGNORECASE),
    # libc internals (common in static builds)
    re.compile(r"^__libc_|^__GI_|^__pthread_|^__do_|^__gconv_", re.IGNORECASE),
    # GCC runtime
    re.compile(r"^__gcc_|^__cxa_|^frame_dummy|^register_tm_clones|^deregister_tm", re.IGNORECASE),
]

# Exact names to always consider library/low-value
LIBRARY_EXACT_NAMES: FrozenSet[str] = frozenset({
    "GENERAL_NAME_free", "GENERAL_NAMES_free", "POLICYINFO_free",
    "POLICY_MAPPING_free", "POLICYQUALINFO_free", "DIST_POINT_free",
    "X509_free", "X509_NAME_free", "X509_CRL_free", "X509_NAME_ENTRY_free",
    "X509_EXTENSION_free", "X509_ALGOR_free", "X509_VERIFY_PARAM_free",
    "X509_SIG_new", "OCSP_RESPID_free", "ASN1_OBJECT_free", "EVP_PKEY_new",
    "PKCS8_PRIV_KEY_INFO_new", "DSA_new", "BIO_vfree",
    "policy_node_free", "policy_data_free", "obj_cleanup_defer",
    "lh_strhash", "ssl_cipher_ptr_id_cmp", "BN_sub", "BN_pseudo_rand",
    "ACCESS_DESCRIPTION_free", "ASN1_STRING_free", "ASN1_TYPE_free",
})

# ---------------------------------------------------------------------------
# Security-relevant imports / callees that make a function interesting
# ---------------------------------------------------------------------------
INTERESTING_CALLEE_PATTERNS: FrozenSet[str] = frozenset({
    # Command execution
    "system", "popen", "pclose", "execve", "execvp", "execl", "execlp",
    "fork", "clone",
    # Network
    "socket", "connect", "bind", "listen", "accept", "send", "sendto",
    "recv", "recvfrom", "gethostbyname", "getaddrinfo",
    # System info gathering (recon)
    "gethostname", "uname", "getifaddrs", "getnameinfo",
    "getpwuid", "getuid", "getenv", "getcwd", "readlink",
    # File I/O
    "fopen", "fopen64", "fwrite", "fread", "open", "write", "read",
    # Process/timing
    "sleep", "usleep", "nanosleep", "poll", "select",
    # Encoding/format
    "snprintf", "sprintf", "sscanf", "strftime",
    # Dynamic loading
    "dlopen", "dlsym",
})

# ---------------------------------------------------------------------------
# String patterns that make a referencing function interesting
# ---------------------------------------------------------------------------
SUSPICIOUS_STRING_PATTERNS: List[re.Pattern[str]] = [
    re.compile(r"googleapis\.com|sheets\.googleapis|oauth2\.googleapis", re.IGNORECASE),
    re.compile(r"https?://[a-z0-9]", re.IGNORECASE),
    re.compile(r"Bearer\s|Authorization:|Content-Type:", re.IGNORECASE),
    re.compile(r"User-Agent:", re.IGNORECASE),
    re.compile(r"\.cfg$|\.conf$|\.ini$|\.json$", re.IGNORECASE),
    re.compile(r"/tmp/|/var/run/|/dev/shm/", re.IGNORECASE),
    re.compile(r"POST |GET |PUT |DELETE |HTTP/", re.IGNORECASE),
    re.compile(r"spreadsheet|batchUpdate|values:", re.IGNORECASE),
    re.compile(r"base64|encode|decode", re.IGNORECASE),
    re.compile(r"cmd|command|shell|bash|/bin/sh", re.IGNORECASE),
    re.compile(r"upload|download|exfil", re.IGNORECASE),
    re.compile(r"Error.*key.*path|Operation not permitted", re.IGNORECASE),
]

# Boost amounts (added to the [0, 1] normalized score)
CALLER_BOOST = 0.35       # Function calls a security-relevant API
STRING_REF_BOOST = 0.30   # Function references a suspicious string
LIBRARY_PENALTY = 0.60    # Known library function — strongly demoted
MAIN_BOOST = 0.50         # Entry-adjacent / main function


def _to_float(value: Any, default: float = 0.0) -> float:
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value.strip())
        except ValueError:
            return default
    return default


def _minmax(values: List[float]) -> List[float]:
    if not values:
        return []
    low = min(values)
    high = max(values)
    if high == low:
        # No spread: keep a stable neutral signal.
        return [0.0 for _ in values]
    scale = high - low
    return [(v - low) / scale for v in values]


def normalize_weights(alpha: float, beta: float) -> Tuple[float, float]:
    alpha = max(0.0, float(alpha))
    beta = max(0.0, float(beta))
    total = alpha + beta
    if total <= 0:
        return 0.5, 0.5
    return alpha / total, beta / total


def is_library_function(name: str) -> bool:
    """Return True if *name* matches known library function patterns."""
    if not name:
        return False
    if name in LIBRARY_EXACT_NAMES:
        return True
    for pat in LIBRARY_NAME_PATTERNS:
        if pat.search(name):
            return True
    return False


def _normalize_callee(name: str) -> str:
    """Strip common import prefixes to bare name for matching."""
    n = (name or "").strip().lower()
    for prefix in ("sym.imp.", "imp.", "sym.", "fcn.", "__imp_", "<external>::"):
        if n.startswith(prefix):
            n = n[len(prefix):]
    return n


def is_interesting_caller(
    func_name: str,
    call_graph_adjacency: Optional[List[Dict[str, Any]]] = None,
) -> bool:
    """Return True if *func_name* directly calls a security-relevant API."""
    if not call_graph_adjacency:
        return False
    for row in call_graph_adjacency:
        if row.get("function") != func_name:
            continue
        for callee in row.get("calls", []):
            if _normalize_callee(callee) in INTERESTING_CALLEE_PATTERNS:
                return True
    return False


def build_interesting_callers_set(
    call_graph_adjacency: Optional[List[Dict[str, Any]]] = None,
) -> Set[str]:
    """Pre-compute the set of all functions that call interesting APIs."""
    result: Set[str] = set()
    if not call_graph_adjacency:
        return result
    for row in call_graph_adjacency:
        func = row.get("function", "")
        for callee in row.get("calls", []):
            if _normalize_callee(callee) in INTERESTING_CALLEE_PATTERNS:
                result.add(func)
                break
    return result


def build_string_ref_functions(
    functions: Iterable[Dict[str, Any]],
    strings: Optional[List[Dict[str, Any]]] = None,
) -> Set[str]:
    """Identify functions whose address range contains references to suspicious strings.

    This uses a heuristic: if a string's address falls within the address range
    [func.address, func.address + func.size] of a function, we consider that
    function to reference that string.  When xref data is available on the string
    entry, that is preferred.
    """
    if not strings:
        return set()

    # Collect suspicious string addresses
    suspicious_addrs: Set[int] = set()
    for s in strings:
        val = s.get("value", "")
        for pat in SUSPICIOUS_STRING_PATTERNS:
            if pat.search(val):
                addr_str = s.get("address", "")
                if addr_str:
                    try:
                        suspicious_addrs.add(int(addr_str, 16) if isinstance(addr_str, str) else int(addr_str))
                    except (ValueError, TypeError):
                        pass
                # Also check xref_from if available
                for xref in s.get("xrefs_from", []):
                    try:
                        suspicious_addrs.add(int(xref, 16) if isinstance(xref, str) else int(xref))
                    except (ValueError, TypeError):
                        pass
                break

    if not suspicious_addrs:
        return set()

    # Map function address ranges
    result: Set[str] = set()
    for f in functions:
        fname = f.get("name", "")
        addr_str = f.get("address", "")
        size = _to_float(f.get("size", 0))
        if not addr_str or size <= 0:
            continue
        try:
            func_start = int(addr_str, 16) if isinstance(addr_str, str) else int(addr_str)
        except (ValueError, TypeError):
            continue
        func_end = func_start + int(size)
        for sa in suspicious_addrs:
            if func_start <= sa <= func_end:
                result.add(fname)
                break

    return result


def prioritize_functions(
    functions: Iterable[Dict[str, Any]],
    alpha: float,
    beta: float,
    *,
    interesting_callers: Optional[Set[str]] = None,
    string_ref_functions: Optional[Set[str]] = None,
    main_functions: Optional[Set[str]] = None,
) -> List[Dict[str, Any]]:
    """Return functions sorted by composite score (descending).

    Adds:
    - ``priority_score``: weighted normalized score in [0, 1+boosts]
    - ``norm_xrefs``: normalized xrefs in [0, 1]
    - ``norm_size``: normalized size in [0, 1]
    - ``is_library``: True if matched as known library function
    - ``is_interesting_caller``: True if calls security-relevant APIs
    - ``has_suspicious_strings``: True if references suspicious strings
    """
    items = [dict(f) for f in functions]
    if not items:
        return []

    interesting_callers = interesting_callers or set()
    string_ref_functions = string_ref_functions or set()
    main_functions = main_functions or set()

    alpha, beta = normalize_weights(alpha, beta)

    xrefs_raw = [_to_float(f.get("xrefs", 0)) for f in items]
    size_raw = [_to_float(f.get("size", 0)) for f in items]
    norm_xrefs = _minmax(xrefs_raw)
    norm_size = _minmax(size_raw)

    scored: List[Dict[str, Any]] = []
    for idx, f in enumerate(items):
        nx = norm_xrefs[idx]
        ns = norm_size[idx]
        base_score = alpha * nx + beta * ns

        fname = f.get("name", "")

        # Library penalty
        lib = is_library_function(fname)
        penalty = LIBRARY_PENALTY if lib else 0.0

        # Behavioral boost: calls interesting APIs
        caller_b = CALLER_BOOST if fname in interesting_callers else 0.0

        # Contextual boost: references suspicious strings
        string_b = STRING_REF_BOOST if fname in string_ref_functions else 0.0

        # Main / entry boost
        main_b = MAIN_BOOST if fname in main_functions else 0.0

        score = max(0.0, base_score + caller_b + string_b + main_b - penalty)

        f["norm_xrefs"] = round(nx, 6)
        f["norm_size"] = round(ns, 6)
        f["priority_score"] = round(score, 6)
        f["is_library"] = lib
        f["is_interesting_caller"] = fname in interesting_callers
        f["has_suspicious_strings"] = fname in string_ref_functions
        scored.append(f)

    scored.sort(
        key=lambda f: (
            f.get("priority_score", 0.0),
            _to_float(f.get("xrefs", 0.0)),
            _to_float(f.get("size", 0.0)),
            str(f.get("name", "")),
        ),
        reverse=True,
    )
    return scored


def apply_priority_to_result(
    result: Dict[str, Any],
    alpha: float,
    beta: float,
    *,
    interesting_callers: Optional[Set[str]] = None,
    string_ref_functions: Optional[Set[str]] = None,
    main_functions: Optional[Set[str]] = None,
) -> Dict[str, Any]:
    """Apply prioritization to a tool result shaped like ``{"ok": True, "functions": [...]}``."""
    if not result.get("ok"):
        return result
    funcs = result.get("functions")
    if not isinstance(funcs, list):
        return result
    alpha_n, beta_n = normalize_weights(alpha, beta)
    result["functions"] = prioritize_functions(
        funcs,
        alpha=alpha_n,
        beta=beta_n,
        interesting_callers=interesting_callers,
        string_ref_functions=string_ref_functions,
        main_functions=main_functions,
    )
    result["priority_weights"] = {"alpha": round(alpha_n, 6), "beta": round(beta_n, 6)}
    return result

