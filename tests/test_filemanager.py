"""File manager move / copy / compress / chmod, including unsafe inputs (panel runs as root)."""
import os
import zipfile
from pathlib import Path

import pytest

from harbor.system import files as fm


def site(tmp_path):
    root = tmp_path / "site"
    for d in ("public", "logs", "tmp"):
        (root / d).mkdir(parents=True)
    return root


def test_move_file_and_folder(tmp_path):
    root = site(tmp_path)
    (root / "public" / "a.txt").write_text("x")
    (root / "public" / "sub").mkdir()
    (root / "public" / "sub" / "b.txt").write_text("y")
    (root / "public" / "dest").mkdir()
    n = fm.move(root, ["public/a.txt", "public/sub"], "public/dest", "root")
    assert n == 2
    assert (root / "public" / "dest" / "a.txt").exists()
    assert (root / "public" / "dest" / "sub" / "b.txt").read_text() == "y"
    assert not (root / "public" / "a.txt").exists()


def test_copy_keeps_original(tmp_path):
    root = site(tmp_path)
    (root / "public" / "a.txt").write_text("x")
    n = fm.copy(root, ["public/a.txt"], "tmp", "root")
    assert n == 1 and (root / "public" / "a.txt").exists() and (root / "tmp" / "a.txt").read_text() == "x"


def test_move_collision_refused(tmp_path):
    root = site(tmp_path)
    (root / "public" / "a.txt").write_text("1")
    (root / "public" / "dest").mkdir()
    (root / "public" / "dest" / "a.txt").write_text("2")
    with pytest.raises(fm.FileError, match="already exists"):
        fm.move(root, ["public/a.txt"], "public/dest", "root")
    assert (root / "public" / "dest" / "a.txt").read_text() == "2"


def test_cannot_move_folder_into_itself(tmp_path):
    root = site(tmp_path)
    (root / "public" / "x").mkdir()
    with pytest.raises(fm.FileError, match="inside itself"):
        fm.move(root, ["public/x"], "public/x", "root")


def test_cannot_move_protected_folder(tmp_path):
    root = site(tmp_path)
    (root / "dest").mkdir()
    with pytest.raises(fm.FileError, match="required folder"):
        fm.move(root, ["public"], "dest", "root")


def test_move_outside_root_blocked(tmp_path):
    root = site(tmp_path)
    (root / "public" / "a.txt").write_text("x")
    with pytest.raises(fm.FileError):
        fm.move(root, ["public/a.txt"], "../..", "root")


def test_compress_selection(tmp_path):
    root = site(tmp_path)
    (root / "public" / "a.txt").write_text("hello")
    (root / "public" / "sub").mkdir()
    (root / "public" / "sub" / "b.txt").write_text("world")
    name = fm.compress(root, ["public/a.txt", "public/sub"], "public", "root", "bundle")
    assert name == "bundle.zip"
    with zipfile.ZipFile(root / "public" / "bundle.zip") as z:
        names = set(z.namelist())
    assert "a.txt" in names and "sub/b.txt" in names


def test_compress_unique_name(tmp_path):
    root = site(tmp_path)
    (root / "public" / "a.txt").write_text("x")
    (root / "public" / "archive.zip").write_text("existing")
    name = fm.compress(root, ["public/a.txt"], "public", "root", "")
    assert name == "archive-1.zip"


def test_chmod(tmp_path):
    root = site(tmp_path)
    f = root / "public" / "a.sh"
    f.write_text("#!/bin/sh")
    fm.set_mode(root, "public/a.sh", "755")
    assert oct(f.stat().st_mode & 0o777) == "0o755"
    with pytest.raises(fm.FileError, match="octal"):
        fm.set_mode(root, "public/a.sh", "oops")
    with pytest.raises(fm.FileError, match="octal"):
        fm.set_mode(root, "public/a.sh", "9999")


def test_bulk_move_over_http(tmp_path):
    from conftest import login, post, csrf, flashes
    from harbor.services import site_root
    from harbor import db as _db
    c = login()
    r = post(c, "/sites", {"domain": "fmbulk.test", "php_version": "8.3", "include_www": "0"})
    sid = int(r.headers["location"].rsplit("/", 1)[1])
    pub = site_root(_db.one("SELECT * FROM sites WHERE id=?", sid)) / "public"
    pub.mkdir(parents=True, exist_ok=True)
    for n in ("a.txt", "b.txt", "c.txt"):
        (pub / n).write_text("x")
    (pub / "dest").mkdir()
    data = {"csrf": csrf(c, f"/sites/{sid}/files?path=public"), "op": "move", "dir": "public",
            "to": "public/dest", "sel": ["public/a.txt", "public/b.txt", "public/c.txt"]}
    c.post(f"/sites/{sid}/files/op", data=data, follow_redirects=False)
    assert all((pub / "dest" / n).exists() for n in ("a.txt", "b.txt", "c.txt"))
    assert not any((pub / n).exists() for n in ("a.txt", "b.txt", "c.txt"))
    assert "Moved 3" in flashes(c, f"/sites/{sid}/files?path=public")[0]
