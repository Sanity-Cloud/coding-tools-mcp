from __future__ import annotations

import base64
import hashlib
import tempfile
import unittest
from pathlib import Path

from coding_tools_mcp.server import Runtime


class FileTransferToolTests(unittest.TestCase):
    def payload(self, result: dict) -> dict:
        structured = result.get("structuredContent")
        self.assertIsInstance(structured, dict)
        return structured

    def test_receive_file_is_binary_safe_and_export_round_trips(self) -> None:
        with tempfile.TemporaryDirectory(prefix="coding-tools-transfer-") as tmp:
            root = Path(tmp)
            runtime = Runtime(root)
            content = b"\x00\xffbinary\r\ncontent\x10"
            digest = hashlib.sha256(content).hexdigest()

            received = runtime.call_tool(
                "receive_file",
                {
                    "path": "nested/payload.bin",
                    "content": base64.b64encode(content).decode("ascii"),
                    "encoding": "base64",
                    "expected_sha256": digest,
                    "create_parent_directories": True,
                },
            )
            received_payload = self.payload(received)
            self.assertTrue(received_payload.get("ok"), received)
            self.assertEqual(received_payload.get("sha256"), digest)
            self.assertEqual((root / "nested" / "payload.bin").read_bytes(), content)

            exported = runtime.call_tool(
                "export_project_file",
                {"path": "nested/payload.bin", "encoding": "base64"},
            )
            exported_payload = self.payload(exported)
            self.assertTrue(exported_payload.get("ok"), exported)
            self.assertEqual(exported_payload.get("sha256"), digest)
            self.assertEqual(base64.b64decode(exported_payload["content"]), content)

    def test_receive_file_requires_explicit_mode_for_existing_nonempty_file(self) -> None:
        with tempfile.TemporaryDirectory(prefix="coding-tools-transfer-") as tmp:
            root = Path(tmp)
            target = root / "existing.txt"
            target.write_text("original", encoding="utf-8")
            runtime = Runtime(root)

            rejected = runtime.call_tool(
                "receive_file",
                {"path": "existing.txt", "content": "replacement", "encoding": "utf8"},
            )
            rejected_payload = self.payload(rejected)
            self.assertFalse(rejected_payload.get("ok"), rejected)
            self.assertEqual(rejected_payload.get("error", {}).get("code"), "MODE_REQUIRED_FOR_EXISTING_FILE")
            self.assertEqual(target.read_text(encoding="utf-8"), "original")

            replaced = runtime.call_tool(
                "receive_file",
                {
                    "path": "existing.txt",
                    "content": "replacement",
                    "encoding": "utf8",
                    "mode": "rewrite",
                },
            )
            self.assertTrue(self.payload(replaced).get("ok"), replaced)
            self.assertEqual(target.read_text(encoding="utf-8"), "replacement")

    def test_receive_file_append_and_sha_mismatch(self) -> None:
        with tempfile.TemporaryDirectory(prefix="coding-tools-transfer-") as tmp:
            root = Path(tmp)
            target = root / "append.txt"
            target.write_text("one", encoding="utf-8")
            runtime = Runtime(root)

            mismatch = runtime.call_tool(
                "receive_file",
                {
                    "path": "append.txt",
                    "content": "two",
                    "encoding": "utf8",
                    "mode": "append",
                    "expected_sha256": "0" * 64,
                },
            )
            mismatch_payload = self.payload(mismatch)
            self.assertFalse(mismatch_payload.get("ok"), mismatch)
            self.assertEqual(mismatch_payload.get("error", {}).get("code"), "SHA256_MISMATCH")
            self.assertEqual(target.read_text(encoding="utf-8"), "one")

            appended = runtime.call_tool(
                "receive_file",
                {"path": "append.txt", "content": "two", "encoding": "utf8", "mode": "append"},
            )
            self.assertTrue(self.payload(appended).get("ok"), appended)
            self.assertEqual(target.read_text(encoding="utf-8"), "onetwo")

    def test_export_project_file_is_bounded_and_returns_continuation(self) -> None:
        with tempfile.TemporaryDirectory(prefix="coding-tools-transfer-") as tmp:
            root = Path(tmp)
            (root / "large.txt").write_text("abcdefghij", encoding="utf-8")
            runtime = Runtime(root)

            first = runtime.call_tool(
                "export_project_file",
                {"path": "large.txt", "encoding": "utf8", "max_bytes": 4},
            )
            first_payload = self.payload(first)
            self.assertTrue(first_payload.get("ok"), first)
            self.assertEqual(first_payload.get("content"), "abcd")
            self.assertTrue(first_payload.get("truncated"))
            self.assertEqual(first_payload.get("next_action", {}).get("arguments", {}).get("offset"), 4)

            second = runtime.call_tool(
                "export_project_file",
                {"path": "large.txt", "encoding": "utf8", "offset": 4, "max_bytes": 6},
            )
            second_payload = self.payload(second)
            self.assertEqual(second_payload.get("content"), "efghij")
            self.assertFalse(second_payload.get("truncated"))

    def test_export_sensitive_file_requires_explicit_allow(self) -> None:
        with tempfile.TemporaryDirectory(prefix="coding-tools-transfer-") as tmp:
            root = Path(tmp)
            (root / ".env").write_text("TOKEN=secret", encoding="utf-8")
            (root / ".env.example").write_text("TOKEN=example", encoding="utf-8")
            runtime = Runtime(root)

            denied = runtime.call_tool("export_project_file", {"path": ".env"})
            denied_payload = self.payload(denied)
            self.assertFalse(denied_payload.get("ok"), denied)
            self.assertEqual(
                denied_payload.get("error", {}).get("code"),
                "SENSITIVE_FILE_REQUIRES_EXPLICIT_ALLOW",
            )

            allowed = runtime.call_tool(
                "export_project_file",
                {"path": ".env", "allow_sensitive_project_file": True},
            )
            allowed_payload = self.payload(allowed)
            self.assertTrue(allowed_payload.get("ok"), allowed)
            self.assertEqual(allowed_payload.get("content"), "TOKEN=secret")

            example = runtime.call_tool("export_project_file", {"path": ".env.example"})
            example_payload = self.payload(example)
            self.assertTrue(example_payload.get("ok"), example)
            self.assertEqual(example_payload.get("content"), "TOKEN=example")

    def test_export_directory_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="coding-tools-transfer-") as tmp:
            root = Path(tmp)
            (root / "folder").mkdir()
            runtime = Runtime(root)

            rejected = runtime.call_tool("export_project_file", {"path": "folder"})
            rejected_payload = self.payload(rejected)
            self.assertFalse(rejected_payload.get("ok"), rejected)
            self.assertEqual(rejected_payload.get("error", {}).get("code"), "NOT_A_FILE")

    def test_export_metadata_only_omits_payload_but_keeps_integrity_metadata(self) -> None:
        with tempfile.TemporaryDirectory(prefix="coding-tools-transfer-") as tmp:
            root = Path(tmp)
            content = b"metadata only"
            target = root / "artifact.bin"
            target.write_bytes(content)
            runtime = Runtime(root)

            exported = runtime.call_tool(
                "export_project_file",
                {"path": "artifact.bin", "encoding": "base64", "include_content": False},
            )
            exported_payload = self.payload(exported)
            self.assertTrue(exported_payload.get("ok"), exported)
            self.assertIsNone(exported_payload.get("content"))
            self.assertEqual(exported_payload.get("byte_count"), len(content))
            self.assertEqual(exported_payload.get("returned_bytes"), len(content))
            self.assertEqual(exported_payload.get("sha256"), hashlib.sha256(content).hexdigest())
            self.assertEqual(exported_payload.get("file_type"), "application/octet-stream")


if __name__ == "__main__":
    unittest.main()
