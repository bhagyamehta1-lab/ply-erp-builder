import hashlib
import unittest

from scripts.enterprise_hq_evidence_verifier import (
    MAX_EVIDENCE_ITEMS,
    MAX_SINGLE_EVIDENCE_BYTES,
    EvidenceVerificationError,
    verify_evidence_bundle,
)


TASK_ID = "HQ-EVIDENCE-001"
PROPOSAL_DIGEST = "a" * 64
RECEIPT_ID = "HQV-EVIDENCE-001"


def entry(path, payload):
    return {"path": path, "sha256": hashlib.sha256(payload).hexdigest(), "size_bytes": len(payload)}


def manifest(entries=None, **overrides):
    value = {
        "schema_version": "1.0.0",
        "task_id": TASK_ID,
        "proposal_digest": PROPOSAL_DIGEST,
        "receipt_id": RECEIPT_ID,
        "evidence": entries if entries is not None else [entry("docs/enterprise-hq-runtime.md", b"approved docs")],
    }
    value.update(overrides)
    return value


class EvidenceVerifierTests(unittest.TestCase):
    def verify(self, value=None, payloads=None, **expected):
        return verify_evidence_bundle(
            value or manifest(),
            payloads if payloads is not None else {"docs/enterprise-hq-runtime.md": b"approved docs"},
            expected_task_id=expected.get("task_id", TASK_ID),
            expected_proposal_digest=expected.get("proposal_digest", PROPOSAL_DIGEST),
            expected_receipt_id=expected.get("receipt_id", RECEIPT_ID),
        )

    def test_valid_bundle_returns_only_integrity_metadata(self):
        result = self.verify()
        self.assertEqual(result["status"], "CONTENT_INTEGRITY_VERIFIED")
        self.assertEqual(result["evidence_count"], 1)
        self.assertEqual(result["total_bytes"], len(b"approved docs"))
        self.assertFalse(result["raw_payloads_retained"])
        self.assertEqual(result["semantic_verification"], "NOT_PERFORMED")
        self.assertFalse(result["identity_authenticated"])
        self.assertFalse(result["execution_authorized"])
        self.assertNotIn("payloads", result)
        self.assertNotIn("content", result)

    def test_manifest_digest_is_deterministic(self):
        self.assertEqual(self.verify()["manifest_digest"], self.verify()["manifest_digest"])

    def test_task_binding_mismatch_rejected(self):
        with self.assertRaisesRegex(EvidenceVerificationError, "TASK_BINDING_MISMATCH"):
            self.verify(task_id="HQ-EVIDENCE-OTHER")

    def test_proposal_binding_mismatch_rejected(self):
        with self.assertRaisesRegex(EvidenceVerificationError, "PROPOSAL_BINDING_MISMATCH"):
            self.verify(proposal_digest="b" * 64)

    def test_receipt_binding_mismatch_rejected(self):
        with self.assertRaisesRegex(EvidenceVerificationError, "RECEIPT_BINDING_MISMATCH"):
            self.verify(receipt_id="HQV-EVIDENCE-OTHER")

    def test_wrong_payload_digest_rejected(self):
        with self.assertRaisesRegex(EvidenceVerificationError, "DIGEST_MISMATCH"):
            self.verify(payloads={"docs/enterprise-hq-runtime.md": b"tampered docs"})

    def test_wrong_payload_size_rejected(self):
        with self.assertRaisesRegex(EvidenceVerificationError, "SIZE_MISMATCH"):
            self.verify(payloads={"docs/enterprise-hq-runtime.md": b"x"})

    def test_missing_payload_rejected(self):
        with self.assertRaisesRegex(EvidenceVerificationError, "PAYLOAD_SET_MISMATCH"):
            self.verify(payloads={})

    def test_extra_payload_rejected(self):
        with self.assertRaisesRegex(EvidenceVerificationError, "PAYLOAD_SET_MISMATCH"):
            self.verify(payloads={"docs/enterprise-hq-runtime.md": b"approved docs", "docs/enterprise-hq-extra.md": b"x"})

    def test_unknown_manifest_field_rejected(self):
        with self.assertRaisesRegex(EvidenceVerificationError, "MANIFEST_SCHEMA_INVALID"):
            self.verify(manifest(extra="no"))

    def test_unsupported_schema_version_rejected(self):
        with self.assertRaisesRegex(EvidenceVerificationError, "VERSION_UNSUPPORTED"):
            self.verify(manifest(schema_version="2.0.0"))

    def test_empty_evidence_list_rejected(self):
        with self.assertRaisesRegex(EvidenceVerificationError, "ITEMS_REQUIRED"):
            self.verify(manifest(entries=[]), payloads={})

    def test_duplicate_paths_rejected(self):
        payload = b"x"
        e = entry("docs/enterprise-hq-runtime.md", payload)
        with self.assertRaisesRegex(EvidenceVerificationError, "PATH_DUPLICATE"):
            self.verify(manifest(entries=[e, e]), payloads={"docs/enterprise-hq-runtime.md": payload})

    def test_unsorted_paths_rejected(self):
        p1, p2 = b"a", b"b"
        e1 = entry("docs/enterprise-hq-zeta.md", p1)
        e2 = entry("docs/enterprise-hq-alpha.md", p2)
        with self.assertRaisesRegex(EvidenceVerificationError, "PATH_ORDER_INVALID"):
            self.verify(manifest(entries=[e1, e2]), payloads={e1["path"]: p1, e2["path"]: p2})

    def test_path_traversal_rejected(self):
        payload = b"x"
        e = entry("docs/../scripts/enterprise_hq_secret.py", payload)
        with self.assertRaisesRegex(EvidenceVerificationError, "PATH_INVALID"):
            self.verify(manifest(entries=[e]), payloads={e["path"]: payload})

    def test_absolute_path_rejected(self):
        payload = b"x"
        e = entry("/docs/enterprise-hq-runtime.md", payload)
        with self.assertRaisesRegex(EvidenceVerificationError, "PATH_INVALID"):
            self.verify(manifest(entries=[e]), payloads={e["path"]: payload})

    def test_backslash_path_rejected(self):
        payload = b"x"
        e = entry("docs\\enterprise-hq-runtime.md", payload)
        with self.assertRaisesRegex(EvidenceVerificationError, "PATH_INVALID"):
            self.verify(manifest(entries=[e]), payloads={e["path"]: payload})

    def test_product_path_rejected(self):
        payload = b"x"
        e = entry("src/ply_erp.py", payload)
        with self.assertRaisesRegex(EvidenceVerificationError, "PATH_OUT_OF_SCOPE"):
            self.verify(manifest(entries=[e]), payloads={e["path"]: payload})

    def test_private_path_rejected(self):
        payload = b"x"
        e = entry("state/ceo_command_audit.json", payload)
        with self.assertRaisesRegex(EvidenceVerificationError, "PATH_OUT_OF_SCOPE"):
            self.verify(manifest(entries=[e]), payloads={e["path"]: payload})

    def test_bad_digest_format_rejected(self):
        value = manifest()
        value["evidence"][0]["sha256"] = "not-a-digest"
        with self.assertRaisesRegex(EvidenceVerificationError, "DIGEST_INVALID"):
            self.verify(value)

    def test_boolean_size_rejected(self):
        value = manifest()
        value["evidence"][0]["size_bytes"] = True
        with self.assertRaisesRegex(EvidenceVerificationError, "SIZE_INVALID"):
            self.verify(value)

    def test_non_bytes_payload_rejected(self):
        with self.assertRaisesRegex(EvidenceVerificationError, "PAYLOAD_TYPE_INVALID"):
            self.verify(payloads={"docs/enterprise-hq-runtime.md": "approved docs"})

    def test_single_item_limit_enforced(self):
        payload = b"x" * (MAX_SINGLE_EVIDENCE_BYTES + 1)
        e = entry("docs/enterprise-hq-large.md", payload)
        with self.assertRaisesRegex(EvidenceVerificationError, "ITEM_SIZE_LIMIT_EXCEEDED"):
            self.verify(manifest(entries=[e]), payloads={e["path"]: payload})

    def test_total_bundle_limit_enforced(self):
        paths = [f"scripts/enterprise_hq_part_{i}.py" for i in range(5)]
        payload = b"x" * MAX_SINGLE_EVIDENCE_BYTES
        entries = [entry(path, payload) for path in paths]
        payloads = {path: payload for path in paths}
        with self.assertRaisesRegex(EvidenceVerificationError, "TOTAL_SIZE_LIMIT_EXCEEDED"):
            self.verify(manifest(entries=entries), payloads=payloads)

    def test_item_count_limit_enforced(self):
        paths = [f"scripts/enterprise_hq_part_{i:02d}.py" for i in range(MAX_EVIDENCE_ITEMS + 1)]
        entries = [entry(path, b"x") for path in paths]
        payloads = {path: b"x" for path in paths}
        with self.assertRaisesRegex(EvidenceVerificationError, "ITEM_LIMIT_EXCEEDED"):
            self.verify(manifest(entries=entries), payloads=payloads)

    def test_multiple_approved_paths_verify(self):
        items = {
            "docs/enterprise-hq-runtime.md": b"docs",
            "scripts/enterprise_hq_evidence_verifier.py": b"code",
            "tests/test_enterprise_hq_evidence_verifier.py": b"tests",
        }
        entries = [entry(path, payload) for path, payload in sorted(items.items())]
        result = self.verify(manifest(entries=entries), payloads=items)
        self.assertEqual(result["evidence_count"], 3)
        self.assertEqual(result["total_bytes"], sum(map(len, items.values())))

    def test_evidence_entry_unknown_field_rejected(self):
        value = manifest()
        value["evidence"][0]["url"] = "https://example.invalid"
        with self.assertRaisesRegex(EvidenceVerificationError, "ENTRY_SCHEMA_INVALID"):
            self.verify(value)

    def test_payloads_must_be_mapping(self):
        with self.assertRaisesRegex(EvidenceVerificationError, "PAYLOAD_MAP_INVALID"):
            self.verify(payloads=[b"x"])


if __name__ == "__main__":
    unittest.main()
