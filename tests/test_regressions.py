from __future__ import annotations

import argparse
import unittest
from unittest.mock import patch

import httpx

from bscan.behavior import BehaviorConfig, BehaviorResult, CookieRule, HeaderRule
from bscan.cli import _scan_quiet
from bscan.http import Client, Response, TransportError
from bscan.version import Range
from bscan.vulndb import VulnDB


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
            with patch.object(client._client, "get", side_effect=httpx.ConnectError("boom")):
                with self.assertRaises(TransportError):
                    client.get("/")
        finally:
            client.close()


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


class _DummyFingerprint:
    is_bitrix = True
    best_core_version = None


def _dummy_fingerprint() -> _DummyFingerprint:
    return _DummyFingerprint()
