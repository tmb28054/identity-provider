"""Phase 3 security-remediation tests (idp-2026-10-06).

Covers the Low finding remediated in Phase 3:

* **Finding 5 (Low)** — no RTO/RPO targets and no resilience manifests. Phase 3
  adds an RPO/RTO/capacity section to ``docs/backups.md`` and resilience
  templates (``PodDisruptionBudget`` + ``topologySpreadConstraints``) under
  ``examples/kubernetes/``. The repo lints ``examples/`` YAML only by parsing
  it, so these tests parse every manifest and assert the new resources are
  present and schema-plausible.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

_MANIFEST_DIR = Path(__file__).resolve().parent.parent / "examples" / "kubernetes"


def _load_docs(path: Path) -> list[dict]:
    """Parse every YAML document in ``path``.

    Args:
        path: Path to a Kubernetes manifest file.

    Returns:
        The non-empty YAML documents contained in the file.
    """
    with path.open(encoding="utf-8") as handle:
        return [doc for doc in yaml.safe_load_all(handle) if doc is not None]


def test_kubernetes_manifests_parse() -> None:
    """Every manifest parses and every document is a schema-plausible object.

    Also asserts the Phase-3 additions: a ``PodDisruptionBudget`` manifest and
    ``topologySpreadConstraints`` on the Deployment pod spec.
    """
    manifests = sorted(_MANIFEST_DIR.glob("*.yaml"))
    assert manifests, "no example kubernetes manifests found"

    kinds: set[str] = set()
    for manifest in manifests:
        docs = _load_docs(manifest)
        assert docs, f"{manifest.name} contained no documents"
        for doc in docs:
            assert isinstance(doc, dict), f"{manifest.name} doc is not a mapping"
            assert "apiVersion" in doc, f"{manifest.name} missing apiVersion"
            assert "kind" in doc, f"{manifest.name} missing kind"
            kinds.add(doc["kind"])

    assert "PodDisruptionBudget" in kinds

    deployment = _load_docs(_MANIFEST_DIR / "deployment.yaml")[0]
    pod_spec = deployment["spec"]["template"]["spec"]
    assert "topologySpreadConstraints" in pod_spec
    constraints = pod_spec["topologySpreadConstraints"]
    assert constraints and isinstance(constraints, list)
    assert constraints[0]["topologyKey"] == "topology.kubernetes.io/zone"


@pytest.mark.smoke
def test_pdb_manifest_present_and_valid() -> None:
    """The PodDisruptionBudget template exists and is well formed."""
    docs = _load_docs(_MANIFEST_DIR / "poddisruptionbudget.yaml")
    assert len(docs) == 1
    pdb = docs[0]
    assert pdb["kind"] == "PodDisruptionBudget"
    assert pdb["spec"]["maxUnavailable"] == 1
