from __future__ import annotations

import argparse
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import httpx

from bscan.behavior import BehaviorConfig, BehaviorResult, CookieRule, HeaderRule
from bscan.cli import (
    _behavior_enabled,
    _build_auth_config,
    _misconfig_enabled,
    _profile_candidates,
    _profile_workers,
    _scan_quiet,
)
from bscan.fingerprint import Fingerprint
from bscan.http import AuthConfig, Client, Response, TransportError
from bscan.misconfig import Check, load_checks, run_checks
from bscan.modules import Module, ModuleScan, scan_modules
from bscan.report import render_json
from bscan.version import Range
from bscan.vulndb import Match, RiskSummary, Vuln, VulnDB, summarize_matches


class RangeParsingTests(unittest.TestCase):
    def test_equal_lower_bounds_keep_exclusive_intersection(self) -> None:
        left = Range.parse(">22.0,>=22.0")
        right = Range.parse(">=22.0,>22.0")

        self.assertEqual(left.format(), ">22.0")
        self.assertEqual(right.format(), ">22.0")


class BehaviorEnablementTests(unittest.TestCase):
    def test_cookie_or_header_rules_enable_behavior_scan(self) -> None:
        cookie_only = BehaviorConfig(cookie_rules=[CookieRule(id="c", cookie="BITRIX_SM", implies=">=22.0")])
        header_only = BehaviorConfig(header_rules=[HeaderRule(id="h", header="X-Powered-By", value_contains="Bitrix", implies=">=22.0")])

        self.assertTrue(cookie_only.enabled)
        self.assertTrue(header_only.enabled)

    def test_scan_quiet_runs_behavior_for_cookie_only_config(self) -> None:
        args = argparse.Namespace(
            workers=1,
            no_modules=True,
            no_misconfig=True,
            no_behavior=False,
            json=False,
            output=None,
            auth=AuthConfig(),
        )
        behavior = BehaviorConfig(cookie_rules=[CookieRule(id="c", cookie="BITRIX_SM", implies=">=22.0")])

        with patch("bscan.cli.fingerprint", return_value=_dummy_fingerprint()):
            with patch("bscan.cli.run_behavior", return_value=BehaviorResult(range=">=22.0")) as run_behavior:
                with patch("bscan.cli._emit"):
                    _scan_quiet(
                        "https://example.com",
                        _DummyClient(),
                        args,
                        VulnDB([]),
                        _DummyHashDB(),
                        checks=[],
                        behavior=behavior,
                    )

        run_behavior.assert_called_once()


class ScanRuntimeFailureTests(unittest.TestCase):
    def test_transport_error_bubbles_up_as_runtime_failure(self) -> None:
        args = argparse.Namespace(
            workers=1,
            no_modules=True,
            no_misconfig=True,
            no_behavior=True,
            json=False,
            output=None,
            auth=AuthConfig(),
        )
        behavior = BehaviorConfig()
        db = VulnDB([])

        with patch("bscan.cli.fingerprint", side_effect=TransportError("GET", "https://example.com/", httpx.ConnectError("boom"))):
            with self.assertRaises(TransportError):
                _scan_quiet(
                    "https://example.com",
                    _DummyClient(),
                    args,
                    db,
                    _DummyHashDB(),
                    checks=[],
                    behavior=behavior,
                )


class ClientTransportTests(unittest.TestCase):
    def test_client_get_raises_transport_error(self) -> None:
        client = Client("https://example.com")
        try:
            with patch.object(client._client, "request", side_effect=httpx.ConnectError("boom")):
                with self.assertRaises(TransportError):
                    client.get("/")
        finally:
            client.close()

    def test_client_receives_auth_headers_and_cookies(self) -> None:
        client = Client(
            "https://example.com",
            auth=AuthConfig(headers={"X-Test": "1"}, cookies={"PHPSESSID": "abc"}),
        )
        try:
            self.assertEqual(client._client.headers["X-Test"], "1")
            self.assertEqual(client._client.cookies.get("PHPSESSID"), "abc")
        finally:
            client.close()


class AuthConfigTests(unittest.TestCase):
    def test_build_auth_config_merges_inline_and_file_cookies(self) -> None:
        with tempfile.NamedTemporaryFile("w+", delete=False) as handle:
            handle.write("# comment\n")
            handle.write("Cookie: BITRIX_SM_UIDH=xyz; PHPSESSID=fromfile\n")
            cookie_path = handle.name

        args = argparse.Namespace(
            header=["Authorization: Bearer token"],
            cookie=["PHPSESSID=inline"],
            cookie_file=cookie_path,
        )

        auth = _build_auth_config(args)

        self.assertEqual(auth.headers["Authorization"], "Bearer token")
        self.assertEqual(auth.cookies["BITRIX_SM_UIDH"], "xyz")
        self.assertEqual(auth.cookies["PHPSESSID"], "fromfile")

    def test_render_json_includes_sanitized_auth_metadata(self) -> None:
        payload = render_json(
            "https://example.com",
            Fingerprint(),
            ModuleScan(),
            [],
            auth=AuthConfig(
                headers={"Authorization": "Bearer token"},
                cookies={"PHPSESSID": "secret-cookie"},
            ),
        )

        self.assertIn('"authenticated": true', payload)
        self.assertIn('"Authorization"', payload)
        self.assertIn('"PHPSESSID"', payload)
        self.assertNotIn("secret-cookie", payload)
        self.assertNotIn("Bearer token", payload)


class ModuleDiscoveryTests(unittest.TestCase):
    def test_scan_modules_discovers_dynamic_candidates_from_assets(self) -> None:
        root = Response(
            url="https://example.com/",
            status=200,
            headers={"content-type": "text/html"},
            text='<script src="/bitrix/js/custommod/app.js"></script>',
            ok=True,
            content=b"",
        )

        with patch("bscan.modules._probe_module") as probe_module:
            def fake_probe(client, name):
                if name == "custommod":
                    return Module(name="custommod", version="3.2.1", source="version.php", evidence_url="https://example.com/bitrix/modules/custommod/install/version.php")
                return None

            probe_module.side_effect = fake_probe
            scan = scan_modules(_DummyClient(), root_html=root, candidates=[], workers=1)

        self.assertEqual(len(scan.modules), 1)
        self.assertEqual(scan.modules[0].name, "custommod")
        self.assertEqual(scan.modules[0].version, "3.2.1")

    def test_module_scan_prefers_stronger_source_even_with_existing_version(self) -> None:
        scan = ModuleScan()

        scan.add(Module(name="custommod", version="1.0.0", source="js_qs", evidence_url="https://example.com/app.js"))
        scan.add(Module(name="custommod", version="1.2.0", source="version.php", evidence_url="https://example.com/version.php"))

        self.assertEqual(len(scan.modules), 1)
        self.assertEqual(scan.modules[0].version, "1.2.0")
        self.assertEqual(scan.modules[0].source, "version.php")


class MisconfigEngineTests(unittest.TestCase):
    def test_run_checks_supports_multi_path_and_new_conditions(self) -> None:
        checks = [
            Check(
                id="BX-BACKUP",
                title="backup",
                severity="critical",
                category="backups",
                paths=["/missing.zip", "/backup.zip"],
                method="HEAD",
                match_all=[{"not_status": [404, 403, 401]}, {"header_missing": "x-bitrix-composite"}],
                match_any=[{"content_type_regex": "(zip|octet-stream)"}],
            )
        ]

        findings = run_checks(_MisconfigClient(), checks)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].category, "backups")
        self.assertEqual(findings[0].url, "https://example.com/backup.zip")

    def test_load_checks_accepts_paths_and_category(self) -> None:
        with tempfile.NamedTemporaryFile("w+", delete=False) as handle:
            handle.write(
                "checks:\n"
                "  - id: TEST-CHECK\n"
                "    title: test\n"
                "    severity: low\n"
                "    category: tools\n"
                "    paths:\n"
                "      - /a\n"
                "      - /b\n"
            )
            config_path = handle.name

        checks = load_checks(Path(config_path))

        self.assertEqual(len(checks), 1)
        self.assertEqual(checks[0].category, "tools")
        self.assertEqual(checks[0].paths, ["/a", "/b"])


class VulnerabilityScoringTests(unittest.TestCase):
    def test_vulndb_match_includes_confidence_metadata(self) -> None:
        db = VulnDB(
            [
                Vuln(
                    id="BX-TEST",
                    title="test vuln",
                    target="landing",
                    severity="high",
                    affected=">=20.0.0,<23.0.0",
                )
            ]
        )

        matches = db.match("landing", "22.5.0", evidence_source="version.php")

        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].confidence_label, "high")
        self.assertEqual(matches[0].match_reason, "affected")
        self.assertEqual(matches[0].evidence_source, "version.php")

    def test_summarize_matches_returns_risk_score(self) -> None:
        matches = [
            Match(
                vuln=Vuln(id="A", title="a", target="core", severity="critical"),
                detected_version="1.0.0",
                confidence=95,
                confidence_label="high",
                evidence_source="hash_match",
                match_reason="fixed_in",
            ),
            Match(
                vuln=Vuln(id="B", title="b", target="vote", severity="medium"),
                detected_version="1.0.0",
                confidence=80,
                confidence_label="medium",
                evidence_source="js_qs",
                match_reason="affected",
            ),
        ]

        summary = summarize_matches(matches)

        self.assertGreater(summary.score, 0)
        self.assertEqual(summary.matched_count, 2)
        self.assertEqual(summary.critical, 1)
        self.assertEqual(summary.medium, 1)

    def test_render_json_includes_risk_summary_and_match_metadata(self) -> None:
        payload = render_json(
            "https://example.com",
            Fingerprint(),
            ModuleScan(),
            [
                Match(
                    vuln=Vuln(id="A", title="a", target="core", severity="high"),
                    detected_version="1.0.0",
                    confidence=90,
                    confidence_label="high",
                    evidence_source="hash_match",
                    match_reason="fixed_in",
                )
            ],
        )

        self.assertIn('"risk_summary"', payload)
        self.assertIn('"confidence_label": "high"', payload)
        self.assertIn('"evidence_source": "hash_match"', payload)


class ScanProfileTests(unittest.TestCase):
    def test_fast_profile_uses_dynamic_only_and_disables_extra_checks(self) -> None:
        self.assertEqual(_profile_candidates("fast"), [])
        self.assertFalse(_misconfig_enabled(argparse.Namespace(no_misconfig=False, profile="fast")))
        self.assertFalse(_behavior_enabled(argparse.Namespace(no_behavior=False, profile="fast")))

    def test_deep_profile_expands_candidates_and_workers(self) -> None:
        candidates = _profile_candidates("deep")
        self.assertIsNotNone(candidates)
        self.assertIn("security", candidates)
        self.assertGreaterEqual(_profile_workers("deep", 8), 12)


class _DummyClient:
    def get(self, path: str, **kwargs) -> Response:
        return Response(
            url=f"https://example.com/{path.lstrip('/')}",
            status=200,
            headers={"content-type": "text/html"},
            text="",
            ok=True,
            content=b"",
        )


class _DummyHashDB:
    paths: list[str] = []

    def __len__(self) -> int:
        return 0


class _MisconfigClient:
    def head(self, path: str, **kwargs) -> Response:
        if path == "/missing.zip":
            return Response(
                url="https://example.com/missing.zip",
                status=404,
                headers={"content-type": "text/html"},
                text="",
                ok=False,
                content=b"",
            )
        return Response(
            url="https://example.com/backup.zip",
            status=200,
            headers={"content-type": "application/zip"},
            text="",
            ok=True,
            content=b"",
        )

    def get(self, path: str, **kwargs) -> Response:
        return self.head(path, **kwargs)


class _DummyFingerprint:
    is_bitrix = True
    best_core_version = None
    hash_version = None
    hash_source = None
    core_js_sha256 = None
    server = None
    powered_by = None
    generator = None
    signals = []
    confidence = 0
    core_version = None
    main_module_version = None


def _dummy_fingerprint() -> _DummyFingerprint:
    return _DummyFingerprint()
