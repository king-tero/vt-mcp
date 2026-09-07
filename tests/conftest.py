from urllib.parse import quote

import pytest


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
def file_hash():
    # SHA-256 of an empty file. Tests never read or upload a sample.
    return "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


@pytest.fixture
def report(file_hash):
    return {
        "data": {
            "id": file_hash,
            "last_analysis_stats": {"undetected": 65, "malicious": 0},
            "type_description": "empty",
            "detections": [],
            "ai_insights": None,
        }
    }


@pytest.fixture
def indicator_report():
    def make(kind, value=None):
        value = (
            value
            or {"url": "https://example.com/", "domain": "example.com", "ip": "192.0.2.1"}[kind]
        )
        identifier = "1" * 64 if kind == "url" else value
        slug = "ip-address" if kind == "ip" else kind
        return {
            "data": {
                "id": identifier,
                "type": "ip_address" if kind == "ip" else kind,
                kind: value,
                "source": "VirusTotal",
                "last_analysis_stats": {"harmless": 3, "undetected": 1},
                "detections": ["clean", "clean"],
                "analysis_date": "2026-08-01T12:34:56+00:00",
                "report_url": f"https://www.virustotal.com/gui/{slug}/{quote(identifier, safe='')}",
                "coverage": {"engines": 2, "categories": ["harmless"]},
            }
        }

    return make
