"""Manifest validation tests  –  a security tool must reject malformed input loudly."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from urd.manifests import ManifestError, ServerManifest, HostConfig, load_manifests_dir


def test_valid_server_manifest_parses():
    m = ServerManifest.from_json({
        "server_id": "admin", "privilege": "high",
        "tools": [{"name": "delete_records", "description": "x", "params_schema": {}}],
    })
    assert m.server_id == "admin" and m.privilege == "high" and m.tools[0].name == "delete_records"


def test_missing_server_id_rejected():
    with pytest.raises(ManifestError):
        ServerManifest.from_json({"privilege": "low", "tools": []})


def test_bad_privilege_rejected():
    with pytest.raises(ManifestError):
        ServerManifest.from_json({"server_id": "x", "privilege": "root", "tools": []})


def test_malformed_tool_rejected():
    with pytest.raises(ManifestError):
        ServerManifest.from_json({"server_id": "x", "privilege": "low", "tools": [{"description": "no name"}]})


def test_bad_host_config_rejected():
    with pytest.raises(ManifestError):
        HostConfig.from_json({"connected_servers": "not-a-list"})


def test_invalid_json_file_rejected(tmp_path: Path):
    (tmp_path / "weather.json").write_text("{ this is not json ")
    with pytest.raises(ManifestError):
        load_manifests_dir(tmp_path)


def test_duplicate_server_ids_rejected(tmp_path: Path):
    (tmp_path / "a.json").write_text(json.dumps({"server_id": "dup", "privilege": "low", "tools": []}))
    (tmp_path / "b.json").write_text(json.dumps({"server_id": "dup", "privilege": "high", "tools": []}))
    with pytest.raises(ManifestError):
        load_manifests_dir(tmp_path)
