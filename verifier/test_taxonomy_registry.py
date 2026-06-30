"""Regression tests for taxonomy extension registry fail-closed validation."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import heso_verify as hv  # noqa: E402


TAXONOMY = """
[[class]]
id = "payment_endpoint"
coarse_verb = "payment"
effect = "spend"

  [[class.predicate]]
  kind = "fact_flag"
  flag = "is_payment"

[[class]]
id = "model_endpoint"
coarse_verb = "llm_call"
effect = "observe"

  [[class.predicate]]
  kind = "fact_flag"
  flag = "is_model_call"

[[class]]
id = "generic_network"
coarse_verb = "http_request"
effect = "transfer_out"

  [[class.predicate]]
  kind = "fact_flag"
  flag = "has_host"

[[class]]
id = "unresolved"
coarse_verb = "tool_call"
effect = "effect_unknown"

  [[class.predicate]]
  kind = "always"
"""

GOOD_REGISTRY = """
[[namespace]]
ns = "heso"
owner = "HESO specification maintainers"

[[extension]]
id = "heso/payment-providers"
kind = "extend"
target_class = "payment_endpoint"
primitive = "move-value"
summary = "Payment hosts."
manifest = "taxonomy/extensions/heso/payment-providers.toml"
vectors = "vectors/heso-1.0-crown-vectors.json#taxonomy_classify"
status = "active"
registered = "2026-06-30"
"""

GOOD_MANIFEST = """
id = "heso/payment-providers"
version = 1
status = "active"
target_class = "payment_endpoint"
primitive = "move-value"

[[predicate]]
kind = "host_set"
host_suffixes = [".example-payments.com"]
"""


def write_bundle(tmp_path: Path, registry: str, manifest: str = GOOD_MANIFEST) -> Path:
    taxonomy_path = tmp_path / "taxonomy.toml"
    taxonomy_path.write_text(TAXONOMY, encoding="utf-8")
    (tmp_path / "registry.toml").write_text(registry, encoding="utf-8")
    manifest_dir = tmp_path / "taxonomy" / "extensions" / "heso"
    manifest_dir.mkdir(parents=True)
    (manifest_dir / "payment-providers.toml").write_text(manifest, encoding="utf-8")
    vectors_dir = tmp_path / "vectors"
    vectors_dir.mkdir()
    (vectors_dir / "heso-1.0-crown-vectors.json").write_text(
        '{"taxonomy_classify":{"cases":[]}}\n',
        encoding="utf-8",
    )
    return taxonomy_path


def load_error(tmp_path: Path, registry: str, manifest: str = GOOD_MANIFEST) -> str:
    taxonomy_path = write_bundle(tmp_path, registry, manifest)
    with pytest.raises((FileNotFoundError, ValueError)) as err:
        hv.load_taxonomy(str(taxonomy_path))
    return str(err.value)


@pytest.mark.parametrize(
    "extension_id",
    ["heso/Bad_Name", "heso/", "heso/payment.providers", "bad ns/payment-providers"],
)
def test_extension_id_must_be_namespaced_lower_kebab(tmp_path: Path, extension_id: str) -> None:
    registry = GOOD_REGISTRY.replace("heso/payment-providers", extension_id)
    assert "<ns>/<lower-kebab-name>" in load_error(tmp_path, registry)


def test_manifest_must_live_under_matching_namespace_path(tmp_path: Path) -> None:
    registry = GOOD_REGISTRY.replace(
        "taxonomy/extensions/heso/payment-providers.toml",
        "../outside.toml",
    )
    assert "manifest must be" in load_error(tmp_path, registry)


def test_vectors_are_required_for_active_extensions(tmp_path: Path) -> None:
    registry = GOOD_REGISTRY.replace(
        'vectors = "vectors/heso-1.0-crown-vectors.json#taxonomy_classify"\n',
        "",
    )
    assert "missing classify vectors" in load_error(tmp_path, registry)


def test_unknown_predicate_parameter_fails_closed(tmp_path: Path) -> None:
    manifest = GOOD_MANIFEST + '\nbogus = "ignored"\n'
    assert "unexpected parameter" in load_error(tmp_path, GOOD_REGISTRY, manifest)


def test_duplicate_namespace_fails_closed(tmp_path: Path) -> None:
    registry = (
        GOOD_REGISTRY
        + """
[[namespace]]
ns = "heso"
owner = "Different owner"
"""
    )
    assert "duplicate namespace" in load_error(tmp_path, registry)


def test_duplicate_extension_id_across_statuses_fails_closed(tmp_path: Path) -> None:
    registry = (
        GOOD_REGISTRY
        + """
[[extension]]
id = "heso/payment-providers"
kind = "extend"
target_class = "payment_endpoint"
primitive = "move-value"
summary = "Retired duplicate."
manifest = "taxonomy/extensions/heso/payment-providers.toml"
vectors = "vectors/heso-1.0-crown-vectors.json#taxonomy_classify"
status = "deprecated"
registered = "2026-06-30"
"""
    )
    assert "duplicate extension id" in load_error(tmp_path, registry)
