"""
Tests for C2 host normalisation and the runtime-endpoint rows built from it.

These back a confirmation check that was a false negative by construction: the
static side of the comparison carries a type prefix, a scheme and often a path
("raw_ip:https://1.2.3.4:8080/gate.php") while the dynamic side reports
"host:port", so a substring test between them could not match even when the
host was byte-identical.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.analysis.apk_static import c2_host, extract_c2_indicators, is_benign_host
from app.analysis.dynamic_verification import is_harness_endpoint
from app.graph.cache import observed_endpoints


def test_static_indicator_and_observed_endpoint_normalise_to_the_same_host():
    """The whole point: these must compare equal, and used not to."""
    assert c2_host("raw_ip:https://128.199.141.233:8080/gate.php") == "128.199.141.233"
    assert c2_host("128.199.141.233:8080") == "128.199.141.233"
    assert c2_host("raw_ip:https://128.199.141.233") == c2_host("128.199.141.233:443")


def test_telegram_token_maps_to_the_host_contact_would_be_observed_on():
    """A bot token is a credential, not an address — contact shows as api.telegram.org."""
    assert c2_host("telegram_bot:8086504175:AAHCOLmDSxahi5mzTI") == "api.telegram.org"


def test_firebase_and_panel_prefixes_reduce_to_their_host():
    assert c2_host("firebase:https://digital-master-gp.firebaseio.com") == "digital-master-gp.firebaseio.com"
    assert c2_host("panel_url:https://evil.example/gate.php") == "evil.example"


def test_non_addresses_are_rejected_rather_than_becoming_hosts():
    """
    Observed landing in the graph as real hosts before the guard existed: the
    literal "null", and "file:" from a single-slash file: URI. A graph claiming
    malware contacted a host named "null" discredits everything beside it.
    """
    for junk in ("null", "http://null", "file:", "file:///data/x", "", "   ", "localhost"):
        assert c2_host(junk) == "", junk


def test_invalid_dotted_quads_are_rejected():
    assert c2_host("999.1.1.1") == ""
    assert c2_host("http://256.1.1.1/") == ""


def test_public_resolvers_are_not_extracted_as_c2():
    """1.1.1.1 DoH was being recorded as attacker infrastructure."""
    out = extract_c2_indicators(["https://1.1.1.1/dns-query?ct=application/dns-udpwireformat"])
    assert not any("1.1.1.1" in i for i in out), out


def test_benign_infrastructure_is_flagged_by_suffix_not_exact_match():
    assert is_benign_host("firebaseinstallations.googleapis.com")
    assert is_benign_host("googleapis.com")
    assert not is_benign_host("dontcryallnight.network")
    assert not is_benign_host("notgoogleapis.com.evil.tld")


def test_harness_traffic_is_recognised():
    """The AVD's own adbd is reachable from inside the emulator and was being
    recorded as infrastructure the sample contacted."""
    for v in ("10.0.2.16:5555", "0.0.0.0:5555", "127.0.0.1:8080", "localhost:1234"):
        assert is_harness_endpoint(v), v
    assert not is_harness_endpoint("154.216.20.57:3434")


def test_observed_endpoints_merges_both_event_sources_and_drops_harness():
    dv = {
        "ran": True,
        "network_observed_all": ["154.216.20.57:3434", "10.0.2.16:5555"],
        "urls_accessed": [
            "http://154.216.20.57/gate.php",              # same host, other source
            "https://firebaseinstallations.googleapis.com/v1/x",
            "https://dontcryallnight.network/a",
        ],
    }
    rows = {r["host"]: r for r in observed_endpoints(dv, ["raw_ip:https://154.216.20.57"])}
    assert set(rows) == {
        "154.216.20.57", "firebaseinstallations.googleapis.com", "dontcryallnight.network",
    }
    assert rows["154.216.20.57"]["statically_predicted"] is True
    assert rows["dontcryallnight.network"]["statically_predicted"] is False
    assert rows["firebaseinstallations.googleapis.com"]["known_benign"] is True
    assert rows["154.216.20.57"]["known_benign"] is False


def test_observed_endpoints_empty_when_dynamic_did_not_run():
    """A pass that never ran observed nothing — it must not contribute nodes."""
    assert observed_endpoints({"ran": False, "urls_accessed": ["http://evil.example"]}, []) == []
    assert observed_endpoints(None, ["raw_ip:http://1.2.3.4"]) == []




def test_cert_thumbprint_uses_the_shared_extractor_not_its_own_scheme_logic():
    """
    extract_cert_thumbprint had its own copy of the scheme lookup that checked
    only v3/v2, so every v1-only (legacy JAR) signed APK got no thumbprint and
    therefore no SIGNED_WITH edge. Fixing the extractor in apk_static alone left
    this second copy broken and the graph unchanged — the duplication was the
    bug. This pins the delegation so the two cannot drift apart again.
    """
    import inspect
    from app.analysis import ingest

    src = inspect.getsource(ingest.extract_cert_thumbprint)
    # Compare code only: the docstring names the old getters when explaining
    # the bug, and matching prose would fail on the explanation itself.
    code = src.replace(ingest.extract_cert_thumbprint.__doc__ or "", "")
    assert "extract_der_certificates" in code, "thumbprint must use the shared extractor"
    assert "get_certificates_der_v2" not in code, "scheme logic must not be duplicated here"
    assert "get_certificates_der_v3" not in code, "scheme logic must not be duplicated here"


def test_v1_only_signed_apk_yields_a_thumbprint():
    """A v1-only APK is signed; it must not read as unsigned."""
    import glob
    from app.analysis.ingest import extract_cert_thumbprint

    hits = glob.glob("data/ttp_apks/02c08ec2675a*.apk")
    if not hits:
        import pytest
        pytest.skip("corpus sample not present")
    from androguard.core.apk import APK
    apk = APK(hits[0])
    assert apk.is_signed_v1() and not apk.is_signed_v2()
    assert extract_cert_thumbprint(apk), "v1-only APK produced no thumbprint"


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))
