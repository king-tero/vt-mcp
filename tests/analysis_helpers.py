"""Innocent, synthetic wave-five protocol fixtures."""

import hashlib

BODY = b"This is an innocent local protocol fixture.\n"
SHA = hashlib.sha256(BODY).hexdigest()
TOKEN = "synthetic-analysis-client-token"
ANALYSIS_ID = "analysis/example?literal%#é"


def analysis_response(identifier=ANALYSIS_ID, sha256=SHA, *, completed=False):
    return {
        "status": "completed" if completed else "pending",
        "analysis_id": identifier,
        "analysis_status": "completed" if completed else "in-progress",
        "sha256": sha256,
        "source": "VirusTotal via VTAI",
        "retrieved_at": "2026-09-06T12:00:00+00:00",
        "analysis_date": "2026-09-05T12:00:00+00:00",
        "stats": {"harmless": 1},
        "results": {
            "Fixture engine": {
                "engine_name": "Fixture engine",
                "engine_version": None,
                "engine_update": None,
                "category": "harmless",
                "result": "Fixture clean label",
                "method": "test",
            }
        },
        "detections": ["Fixture clean label"],
        "coverage": {"engines": 1, "categories": ["harmless"]},
        "report_url": f"https://www.virustotal.com/gui/file/{sha256}",
        "next_poll_after_seconds": None if completed else 5,
        "pending_reason": None if completed else "processing",
    }


def submission_response(sha256=SHA, size=None, *, status="submitted"):
    size = len(BODY) if size is None else size
    return {
        "status": status,
        "mode": "standard",
        "submission_id": sha256,
        "sha256": sha256,
        "size": size,
        "analysis_id": ANALYSIS_ID if status == "submitted" else None,
        "analysis_status": None,
        "next_poll_after_seconds": 5 if status == "submitted" else None,
        "can_resubmit": False,
        "report": {
            "data": {
                "id": sha256,
                "last_analysis_stats": {"harmless": 1},
                "detections": [],
                "type_description": None,
                "ai_insights": None,
            }
        }
        if status == "exists"
        else None,
    }
