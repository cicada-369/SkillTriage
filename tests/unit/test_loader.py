import gzip
import io
import os
import stat
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

from skilltriage.loader import LoaderLimits, PreparedTarget, TargetError


class DirectoryLoaderTests(unittest.TestCase):
    def test_records_text_binary_symlink_and_skips_vendor(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "SKILL.md").write_text("---\nname: demo\n---\nbody\n")
            (root / "tool").write_bytes(b"\x7fELF" + b"\x00" * 32)
            (root / ".hidden").write_text("hidden\n")
            (root / "node_modules" / "pkg").mkdir(parents=True)
            (root / "node_modules" / "pkg" / "index.js").write_text("x\n")
            os.symlink("/etc/passwd", root / "link")
            with PreparedTarget(root, LoaderLimits()) as tree:
                records = tree.by_path()
                self.assertEqual(records["tool"].kind, "binary")
                self.assertEqual(records["tool"].magic, "ELF executable")
                self.assertTrue(records["link"].is_symlink)
                self.assertEqual(records["link"].link_target, "/etc/passwd")
                self.assertNotIn("node_modules/pkg/index.js", records)
                self.assertTrue(any("vendor" in note for note in tree.notes))

    def test_fifo_is_recorded_not_read(self):
        if not hasattr(os, "mkfifo"):
            self.skipTest("mkfifo unavailable")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "SKILL.md").write_text("---\nname: demo\n---\n")
            os.mkfifo(root / "pipe")
            with PreparedTarget(root, LoaderLimits()) as tree:
                record = tree.by_path()["pipe"]
                self.assertEqual(record.kind, "device")

    def test_truncation_and_hash(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "SKILL.md").write_text("---\nname: demo\n---\n")
            (root / "big.txt").write_text("a" * 100)
            with PreparedTarget(root, LoaderLimits(max_file_bytes=10)) as tree:
                record = tree.by_path()["big.txt"]
                self.assertTrue(record.truncated)
                self.assertEqual(len(record.text), 10)
                self.assertEqual(len(record.sha256), 64)

    def test_content_hash_is_deterministic_and_changes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "SKILL.md").write_text("---\nname: demo\n---\n")
            (root / "a.txt").write_text("one")
            with PreparedTarget(root, LoaderLimits()) as tree:
                first = tree.content_hash()
            with PreparedTarget(root, LoaderLimits()) as tree:
                second = tree.content_hash()
            self.assertEqual(first, second)
            (root / "a.txt").write_text("two")
            with PreparedTarget(root, LoaderLimits()) as tree:
                third = tree.content_hash()
            self.assertNotEqual(first, third)

    def test_max_files_cap(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "SKILL.md").write_text("---\nname: demo\n---\n")
            for index in range(5):
                (root / f"f{index}.txt").write_text("x")
            with PreparedTarget(root, LoaderLimits(max_files=2)) as tree:
                self.assertTrue(any("stopped after" in note for note in tree.notes))

    def test_max_files_counts_directories(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "SKILL.md").write_text("---\nname: demo\n---\n")
            for index in range(20):
                (root / f"dir{index}").mkdir()
            with PreparedTarget(root, LoaderLimits(max_files=5)) as tree:
                self.assertTrue(any("stopped after" in note for note in tree.notes))

    def test_max_files_counts_symlinks(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for index in range(4):
                os.symlink("/etc/passwd", root / f"link{index}")
            with PreparedTarget(root, LoaderLimits(max_files=2)) as tree:
                self.assertEqual(len(tree.records), 2)
                self.assertTrue(any("stopped after" in note for note in tree.notes))

    def test_symlinked_target_root_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            real = Path(tmp) / "real"
            real.mkdir()
            (real / "SKILL.md").write_text("---\nname: demo\n---\n")
            link = Path(tmp) / "link"
            os.symlink(real, link)
            with self.assertRaises(TargetError):
                with PreparedTarget(link, LoaderLimits()):
                    pass


class ArchiveLoaderTests(unittest.TestCase):
    def _zip(self, root: Path) -> Path:
        path = root / "skill.zip"
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("SKILL.md", "---\nname: demo\n---\nbody\n")
            archive.writestr("scripts/run.sh", "echo hello\n")
        return path

    def test_zip_extracts_safely(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self._zip(Path(tmp))
            with PreparedTarget(path, LoaderLimits()) as tree:
                self.assertEqual(tree.kind, "archive")
                self.assertIn("SKILL.md", tree.relpaths())
                self.assertIn("scripts/run.sh", tree.relpaths())

    def test_zip_slip_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "evil.zip"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("../escape.txt", "x")
            with self.assertRaises(TargetError):
                with PreparedTarget(path, LoaderLimits()):
                    pass

    def test_zip_symlink_member_is_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "links.zip"
            info = zipfile.ZipInfo("link")
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("SKILL.md", "---\nname: demo\n---\n")
                archive.writestr(info, "/etc/passwd")
            with PreparedTarget(path, LoaderLimits()) as tree:
                self.assertTrue(any("symlink" in issue for issue in tree.archive_issues))

    def test_zip_bomb_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bomb.zip"
            with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("SKILL.md", "---\nname: demo\n---\n")
                archive.writestr("big.bin", b"\x00" * 100_000)
            limits = LoaderLimits(max_archive_uncompressed=1_000, max_compression_ratio=2.0)
            with self.assertRaises(TargetError):
                with PreparedTarget(path, limits):
                    pass

    def test_tar_traversal_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "evil.tar.gz"
            with tarfile.open(path, "w:gz") as archive:
                info = tarfile.TarInfo("../escape.txt")
                payload = b"x"
                info.size = len(payload)
                archive.addfile(info, io.BytesIO(payload))
            with self.assertRaises(TargetError):
                with PreparedTarget(path, LoaderLimits()):
                    pass

    def test_non_archive_file_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "not-a-skill.txt"
            path.write_text("hello")
            with self.assertRaises(TargetError):
                with PreparedTarget(path, LoaderLimits()):
                    pass

    def test_duplicate_zip_member_is_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "duplicate.zip"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("SKILL.md", "---\nname: one\n---\n")
                archive.writestr("SKILL.md", "---\nname: two\n---\n")
            with PreparedTarget(path, LoaderLimits()) as tree:
                self.assertTrue(
                    any(
                        "duplicate archive member" in issue
                        for issue in tree.archive_issues
                    )
                )

    def test_zip_entry_count_is_checked_before_infolist(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "many.zip"
            with zipfile.ZipFile(path, "w") as archive:
                for index in range(20):
                    archive.writestr(f"f{index}.txt", "x")
            with self.assertRaises(TargetError):
                with PreparedTarget(path, LoaderLimits(max_archive_entries=10)):
                    pass

    def test_windows_drive_component_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "drive.zip"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("SKILL.md", "---\nname: demo\n---\n")
                archive.writestr("a/D:evil", "x")
            with self.assertRaises(TargetError):
                with PreparedTarget(path, LoaderLimits()):
                    pass

    def test_windows_reserved_name_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "reserved.zip"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("SKILL.md", "---\nname: demo\n---\n")
                archive.writestr("CON", "x")
            with self.assertRaises(TargetError):
                with PreparedTarget(path, LoaderLimits()):
                    pass

    def test_compressed_tar_expansion_is_bounded(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bomb.tar.gz"
            path.write_bytes(gzip.compress(b"\x00" * 20_000))
            with self.assertRaises(TargetError):
                with PreparedTarget(path, LoaderLimits(max_archive_uncompressed=1_000)):
                    pass

    def test_corrupt_zip_is_a_target_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "broken.zip"
            path.write_bytes(b"PK\x03\x04" + b"\x00" * 32)
            with self.assertRaises(TargetError):
                with PreparedTarget(path, LoaderLimits()):
                    pass

    def test_truncated_tar_is_a_target_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "broken.tar.gz"
            path.write_bytes(b"\x1f\x8b" + b"\x00" * 32)
            with self.assertRaises(TargetError):
                with PreparedTarget(path, LoaderLimits()):
                    pass


if __name__ == "__main__":
    unittest.main()
