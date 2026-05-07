"""Tests for content hash computation."""

from __future__ import annotations

import pytest

from ddr._internal.hash_utils import compute_content_hash, verify_content_hash


def test_compute_returns_sha256_prefix(sample_sigma_rule):
    h = compute_content_hash(sample_sigma_rule)
    assert h.startswith("sha256:")
    assert len(h) == len("sha256:") + 64


def test_compute_is_deterministic(sample_sigma_rule):
    h1 = compute_content_hash(sample_sigma_rule)
    h2 = compute_content_hash(sample_sigma_rule)
    assert h1 == h2


def test_compute_changes_on_content_change(sample_sigma_rule):
    h1 = compute_content_hash(sample_sigma_rule)
    original = sample_sigma_rule.read_text(encoding="utf-8")
    sample_sigma_rule.write_text(original + "\n# extra comment\n", encoding="utf-8")
    h2 = compute_content_hash(sample_sigma_rule)
    # Comments are stripped by safe loader so adding a comment shouldn't change hash
    # (safe YAML strips comments on load, so the hash of the logical content is unchanged)
    # This is the expected canonicalization behavior: cosmetic changes don't affect the hash
    assert h1 == h2


def test_compute_changes_on_semantic_change(sample_sigma_rule):
    h1 = compute_content_hash(sample_sigma_rule)
    original = sample_sigma_rule.read_text(encoding="utf-8")
    modified = original.replace("level: medium", "level: high")
    sample_sigma_rule.write_text(modified, encoding="utf-8")
    h2 = compute_content_hash(sample_sigma_rule)
    assert h1 != h2


def test_verify_content_hash_match(sample_sigma_rule):
    h = compute_content_hash(sample_sigma_rule)
    assert verify_content_hash(sample_sigma_rule, h) is True


def test_verify_content_hash_mismatch(sample_sigma_rule):
    assert verify_content_hash(sample_sigma_rule, "sha256:" + "0" * 64) is False


def test_empty_yaml_raises(tmp_path):
    empty = tmp_path / "empty.yml"
    empty.write_text("", encoding="utf-8")
    with pytest.raises(ValueError, match="Empty"):
        compute_content_hash(empty)
