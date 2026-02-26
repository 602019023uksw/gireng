"""Tests for composite function prioritization (xrefs + size + behavioural signals)."""

from copy import deepcopy

import pytest

from ghidra_agent.function_priority import (
    CALLER_BOOST,
    LIBRARY_PENALTY,
    MAIN_BOOST,
    STRING_REF_BOOST,
    apply_priority_to_result,
    build_interesting_callers_set,
    build_string_ref_functions,
    is_library_function,
    normalize_weights,
    prioritize_functions,
)


# ── normalize_weights ──────────────────────────────────────────────────────

def test_normalize_weights_handles_zero_total():
    alpha, beta = normalize_weights(0.0, 0.0)
    assert alpha == 0.5
    assert beta == 0.5


# ── is_library_function ────────────────────────────────────────────────────

class TestIsLibraryFunction:
    @pytest.mark.parametrize("name", [
        "SSL_connect", "ssl3_read_bytes", "TLS_method",
        "X509_free", "ASN1_OBJECT_free", "BIO_new",
        "SHA256_Update", "AES_encrypt", "SEED_encrypt",
        "d2i_X509", "i2d_X509", "EVP_DigestInit",
        "inflateInit2", "deflateEnd", "crc32",
        "__libc_start_main", "__GI_strlen",
        "__cxa_atexit", "frame_dummy",
        "GENERAL_NAME_free",  # exact name
    ])
    def test_detects_library_names(self, name):
        assert is_library_function(name) is True

    @pytest.mark.parametrize("name", [
        "main", "FUN_004095c0", "FUN_00408b20",
        "entry", "sub_401000", "my_handler",
        "_start", "real_main",
    ])
    def test_does_not_flag_application_functions(self, name):
        assert is_library_function(name) is False

    def test_empty_name_returns_false(self):
        assert is_library_function("") is False


# ── build_interesting_callers_set ──────────────────────────────────────────

class TestBuildInterestingCallersSet:
    def test_identifies_callers_of_security_apis(self):
        call_graph = [
            {"function": "FUN_main", "calls": ["popen", "sleep"]},
            {"function": "FUN_helper", "calls": ["printf", "strlen"]},
            {"function": "FUN_net", "calls": ["socket", "connect"]},
        ]
        result = build_interesting_callers_set(call_graph)
        assert result == {"FUN_main", "FUN_net"}

    def test_strips_import_prefixes(self):
        call_graph = [
            {"function": "FUN_a", "calls": ["sym.imp.popen"]},
            {"function": "FUN_b", "calls": ["imp.gethostname"]},
            {"function": "FUN_c", "calls": ["<external>::getenv"]},
        ]
        result = build_interesting_callers_set(call_graph)
        assert result == {"FUN_a", "FUN_b", "FUN_c"}

    def test_returns_empty_set_when_no_graph(self):
        assert build_interesting_callers_set(None) == set()
        assert build_interesting_callers_set([]) == set()

    def test_ignores_non_interesting_callees(self):
        call_graph = [
            {"function": "FUN_boring", "calls": ["strlen", "memcpy", "printf"]},
        ]
        assert build_interesting_callers_set(call_graph) == set()


# ── build_string_ref_functions ─────────────────────────────────────────────

class TestBuildStringRefFunctions:
    def _make_funcs(self):
        return [
            {"name": "FUN_a", "address": "0x1000", "size": 200},
            {"name": "FUN_b", "address": "0x2000", "size": 100},
        ]

    def test_matches_function_by_string_address_range(self):
        funcs = self._make_funcs()
        strings = [
            {"value": "https://sheets.googleapis.com/v4", "address": "0x1050"},
        ]
        result = build_string_ref_functions(funcs, strings)
        assert "FUN_a" in result
        assert "FUN_b" not in result

    def test_matches_multiple_suspicious_patterns(self):
        funcs = self._make_funcs()
        strings = [
            {"value": "/tmp/kworofd.cfg", "address": "0x1010"},
            {"value": "User-Agent: Mozilla/5.0", "address": "0x2010"},
        ]
        result = build_string_ref_functions(funcs, strings)
        assert "FUN_a" in result
        assert "FUN_b" in result

    def test_returns_empty_when_no_strings(self):
        funcs = self._make_funcs()
        assert build_string_ref_functions(funcs, None) == set()
        assert build_string_ref_functions(funcs, []) == set()

    def test_ignores_non_suspicious_strings(self):
        funcs = self._make_funcs()
        strings = [
            {"value": "Hello, World!", "address": "0x1050"},
            {"value": "some regular string", "address": "0x2050"},
        ]
        result = build_string_ref_functions(funcs, strings)
        assert result == set()


# ── prioritize_functions ───────────────────────────────────────────────────

def test_prioritize_functions_adds_scores_and_sorts_descending():
    funcs = [
        {"name": "tiny_hot", "xrefs": 50, "size": 10},
        {"name": "big_cold", "xrefs": 1, "size": 1000},
        {"name": "balanced", "xrefs": 40, "size": 800},
    ]

    ranked = prioritize_functions(funcs, alpha=0.7, beta=0.3)

    assert len(ranked) == 3
    assert "priority_score" in ranked[0]
    assert "norm_xrefs" in ranked[0]
    assert "norm_size" in ranked[0]
    assert ranked[0]["priority_score"] >= ranked[1]["priority_score"] >= ranked[2]["priority_score"]
    assert ranked[0]["name"] == "balanced"


def test_library_functions_are_demoted():
    """SSL_connect should rank below a smaller app function with caller + string boosts."""
    funcs = [
        {"name": "SSL_connect", "xrefs": 1000, "size": 5000},
        {"name": "FUN_app_logic", "xrefs": 5, "size": 200},
        {"name": "SHA256_Update", "xrefs": 400, "size": 2000},
        {"name": "FUN_other", "xrefs": 10, "size": 300},
    ]
    ranked = prioritize_functions(
        funcs, alpha=0.7, beta=0.3,
        interesting_callers={"FUN_app_logic"},
        string_ref_functions={"FUN_app_logic"},
    )
    # With caller + string boost, app function should beat penalized lib funcs.
    assert ranked[0]["name"] == "FUN_app_logic"
    assert ranked[0]["is_library"] is False
    assert ranked[0]["is_interesting_caller"] is True
    # Both SSL_connect and SHA256_Update should be flagged as library
    lib_names = {f["name"] for f in ranked if f["is_library"]}
    assert "SSL_connect" in lib_names
    assert "SHA256_Update" in lib_names


def test_interesting_caller_boost_applied():
    funcs = [
        {"name": "FUN_a", "xrefs": 10, "size": 100},
        {"name": "FUN_b", "xrefs": 10, "size": 100},
    ]
    ranked = prioritize_functions(
        funcs, alpha=0.7, beta=0.3,
        interesting_callers={"FUN_a"},
    )
    assert ranked[0]["name"] == "FUN_a"
    assert ranked[0]["is_interesting_caller"] is True
    score_diff = ranked[0]["priority_score"] - ranked[1]["priority_score"]
    assert abs(score_diff - CALLER_BOOST) < 0.01


def test_string_ref_boost_applied():
    funcs = [
        {"name": "FUN_a", "xrefs": 10, "size": 100},
        {"name": "FUN_b", "xrefs": 10, "size": 100},
    ]
    ranked = prioritize_functions(
        funcs, alpha=0.7, beta=0.3,
        string_ref_functions={"FUN_b"},
    )
    assert ranked[0]["name"] == "FUN_b"
    assert ranked[0]["has_suspicious_strings"] is True
    score_diff = ranked[0]["priority_score"] - ranked[1]["priority_score"]
    assert abs(score_diff - STRING_REF_BOOST) < 0.01


def test_main_boost_applied():
    funcs = [
        {"name": "FUN_a", "xrefs": 10, "size": 100},
        {"name": "main", "xrefs": 10, "size": 100},
    ]
    ranked = prioritize_functions(
        funcs, alpha=0.7, beta=0.3,
        main_functions={"main"},
    )
    assert ranked[0]["name"] == "main"
    score_diff = ranked[0]["priority_score"] - ranked[1]["priority_score"]
    assert abs(score_diff - MAIN_BOOST) < 0.01


def test_combined_boosts_stack():
    """A function with all boosts should score much higher than one with none."""
    funcs = [
        {"name": "FUN_plain", "xrefs": 100, "size": 500},
        {"name": "FUN_super", "xrefs": 5, "size": 50},
    ]
    ranked = prioritize_functions(
        funcs, alpha=0.7, beta=0.3,
        interesting_callers={"FUN_super"},
        string_ref_functions={"FUN_super"},
        main_functions={"FUN_super"},
    )
    assert ranked[0]["name"] == "FUN_super"
    # Should have all three boosts
    expected_min_boost = CALLER_BOOST + STRING_REF_BOOST + MAIN_BOOST
    assert ranked[0]["priority_score"] >= expected_min_boost - 0.01


def test_score_never_negative():
    """Library penalty should clamp to 0, not go negative."""
    funcs = [
        {"name": "SSL_connect", "xrefs": 0, "size": 0},
    ]
    ranked = prioritize_functions(funcs, alpha=0.7, beta=0.3)
    assert ranked[0]["priority_score"] >= 0.0


def test_realistic_static_binary_ordering():
    """Simulate kworofd-like scenario: OpenSSL lib funcs with huge xrefs vs
    small app functions with interesting callees and string refs."""
    funcs = [
        {"name": "SEED_encrypt", "xrefs": 500, "size": 3000},
        {"name": "SSL_connect", "xrefs": 1733, "size": 8000},
        {"name": "SHA256_Update", "xrefs": 800, "size": 2000},
        {"name": "FUN_004095c0", "xrefs": 2, "size": 600},   # main-like
        {"name": "FUN_00408b20", "xrefs": 1, "size": 350},   # sysinfo
        {"name": "FUN_00407310", "xrefs": 3, "size": 200},   # cmd_exec
    ]
    ranked = prioritize_functions(
        funcs, alpha=0.7, beta=0.3,
        interesting_callers={"FUN_004095c0", "FUN_00408b20", "FUN_00407310"},
        string_ref_functions={"FUN_004095c0", "FUN_00408b20", "FUN_00407310"},
        main_functions={"FUN_004095c0"},
    )
    # FUN_004095c0 (main+caller+string) should be first
    assert ranked[0]["name"] == "FUN_004095c0"
    # All app functions should rank above all library functions
    app_names = {"FUN_004095c0", "FUN_00408b20", "FUN_00407310"}
    lib_names = {"SEED_encrypt", "SSL_connect", "SHA256_Update"}
    app_positions = [i for i, r in enumerate(ranked) if r["name"] in app_names]
    lib_positions = [i for i, r in enumerate(ranked) if r["name"] in lib_names]
    assert max(app_positions) < min(lib_positions), (
        f"App functions should all rank above library functions. "
        f"Order: {[r['name'] for r in ranked]}"
    )


# ── apply_priority_to_result ──────────────────────────────────────────────

def test_apply_priority_to_result_enriches_payload():
    result = {
        "ok": True,
        "functions": [
            {"name": "f1", "xrefs": 2, "size": 10},
            {"name": "f2", "xrefs": 5, "size": 8},
        ],
    }

    updated = apply_priority_to_result(deepcopy(result), alpha=0.8, beta=0.2)

    assert updated["ok"] is True
    assert updated["priority_weights"] == {"alpha": 0.8, "beta": 0.2}
    assert updated["functions"][0]["name"] == "f2"
    assert all("priority_score" in f for f in updated["functions"])


def test_apply_priority_to_result_noop_on_error_payload():
    result = {"ok": False, "error": "boom"}
    updated = apply_priority_to_result(deepcopy(result), alpha=0.7, beta=0.3)
    assert updated == result


def test_apply_priority_passes_through_behavioral_signals():
    result = {
        "ok": True,
        "functions": [
            {"name": "SSL_connect", "xrefs": 100, "size": 500},
            {"name": "FUN_main", "xrefs": 5, "size": 200},
            {"name": "EVP_DigestInit", "xrefs": 80, "size": 300},
            {"name": "FUN_worker", "xrefs": 10, "size": 150},
        ],
    }
    updated = apply_priority_to_result(
        deepcopy(result), alpha=0.7, beta=0.3,
        interesting_callers={"FUN_main"},
        string_ref_functions={"FUN_main"},
    )
    # FUN_main should be first due to caller + string boost vs SSL penalty
    assert updated["functions"][0]["name"] == "FUN_main"
    assert updated["functions"][0]["is_interesting_caller"] is True
    assert updated["functions"][0]["has_suspicious_strings"] is True
    # Library functions should be flagged
    lib_funcs = [f for f in updated["functions"] if f["is_library"]]
    assert len(lib_funcs) == 2
    assert {f["name"] for f in lib_funcs} == {"SSL_connect", "EVP_DigestInit"}
