"""File-manager archive extraction, including hostile archives (panel runs as root)."""
import io
import os
import tarfile
import zipfile
from pathlib import Path

import pytest

from harbor.system import files as fm


def site(tmp_path):
    root = tmp_path / "site"
    (root / "public").mkdir(parents=True)
    return root


def test_extract_zip(tmp_path):
    root = site(tmp_path)
    zp = root / "public" / "bundle.zip"
    with zipfile.ZipFile(zp, "w") as z:
        z.writestr("index.php", "<?php echo 1;")
        z.writestr("css/app.css", "body{}")
    n = fm.extract(root, "public/bundle.zip", "root")
    assert n == 2
    assert (root / "public" / "index.php").read_text() == "<?php echo 1;"
    assert (root / "public" / "css" / "app.css").exists()


def test_extract_targz(tmp_path):
    root = site(tmp_path)
    tp = root / "public" / "site.tar.gz"
    with tarfile.open(tp, "w:gz") as t:
        data = b"hello"
        info = tarfile.TarInfo("app/index.html")
        info.size = len(data)
        t.addfile(info, io.BytesIO(data))
    n = fm.extract(root, "public/site.tar.gz", "root")
    assert n == 1 and (root / "public" / "app" / "index.html").read_bytes() == b"hello"


def test_zip_slip_blocked(tmp_path):
    root = site(tmp_path)
    zp = root / "public" / "evil.zip"
    with zipfile.ZipFile(zp, "w") as z:
        z.writestr("../../escape.php", "pwned")
    with pytest.raises(fm.FileError):
        fm.extract(root, "public/evil.zip", "root")
    assert not (tmp_path / "escape.php").exists()


def test_absolute_path_blocked(tmp_path):
    root = site(tmp_path)
    tp = root / "public" / "abs.tar"
    with tarfile.open(tp, "w") as t:
        data = b"x"
        info = tarfile.TarInfo("/etc/evil.php")
        info.size = len(data)
        t.addfile(info, io.BytesIO(data))
    # leading slash is stripped to a safe relative path, extracted inside the folder, never to /etc
    fm.extract(root, "public/abs.tar", "root")
    assert (root / "public" / "etc" / "evil.php").exists()


def test_symlink_in_tar_skipped(tmp_path):
    root = site(tmp_path)
    tp = root / "public" / "link.tar"
    with tarfile.open(tp, "w") as t:
        link = tarfile.TarInfo("sneaky")
        link.type = tarfile.SYMTYPE
        link.linkname = "/etc/passwd"
        t.addfile(link)
    fm.extract(root, "public/link.tar", "root")
    assert not (root / "public" / "sneaky").exists()        # the symlink was skipped


def test_zip_bomb_capped(tmp_path):
    root = site(tmp_path)
    zp = root / "public" / "big.zip"
    with zipfile.ZipFile(zp, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("huge.bin", b"\0" * (5 * 1024 * 1024))
    with pytest.raises(fm.FileError, match="over the"):
        fm.extract(root, "public/big.zip", "root", max_bytes=1024 * 1024)
    assert not (root / "public" / "huge.bin").exists()


def test_listing_flags_archive(tmp_path):
    root = site(tmp_path)
    (root / "public" / "a.zip").write_bytes(b"PK\x03\x04")
    (root / "public" / "b.txt").write_text("x")
    _, entries = fm.listing(root, "public")
    flags = {e["name"]: e["is_archive"] for e in entries}
    assert flags["a.zip"] is True and flags["b.txt"] is False


def test_not_archive_rejected(tmp_path):
    root = site(tmp_path)
    (root / "public" / "notes.txt").write_text("x")
    with pytest.raises(fm.FileError, match="can extract"):
        fm.extract(root, "public/notes.txt", "root")
