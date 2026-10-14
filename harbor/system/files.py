"""File manager confined to a site's folder.

The panel runs as root, so every path is fully resolved (following symlinks)
and must stay inside the site root; a symlink pointing outside is refused."""
import os
import shutil
from datetime import datetime
from pathlib import Path

from .. import config
from .runner import chown

TEXT_EXT = {".php", ".html", ".htm", ".css", ".js", ".json", ".txt", ".md", ".xml", ".svg", ".ini",
            ".conf", ".htaccess", ".env", ".yml", ".yaml", ".sql", ".csv", ".log", ".py", ".sh", ".ts", ".twig"}


class FileError(Exception):
    pass


def safe_path(root: Path, rel: str) -> Path:
    root = root.resolve()
    target = (root / (rel or "").lstrip("/")).resolve()
    if target != root and root not in target.parents:
        raise FileError("Path is outside the site folder")
    return target


def relpath(root: Path, path: Path) -> str:
    r = str(path.relative_to(root.resolve()))
    return "" if r == "." else r


def listing(root: Path, rel: str):
    d = safe_path(root, rel)
    if not d.is_dir():
        raise FileError("Not a folder")
    entries = []
    for e in d.iterdir():
        try:
            st = e.lstat()
        except OSError:
            continue
        entries.append({
            "name": e.name,
            "rel": relpath(root, d / e.name),
            "is_dir": e.is_dir() and not e.is_symlink(),
            "is_link": e.is_symlink(),
            "size": st.st_size,
            "mtime": datetime.fromtimestamp(st.st_mtime),
            "mode": oct(st.st_mode & 0o777)[2:],
            "editable": is_text(e),
        })
    entries.sort(key=lambda x: (not x["is_dir"], x["name"].lower()))
    return d, entries


def is_text(path: Path) -> bool:
    if path.is_dir():
        return False
    return path.suffix.lower() in TEXT_EXT or (path.name.startswith(".") and path.suffix == "")


def read_text(root: Path, rel: str) -> str:
    f = safe_path(root, rel)
    if not f.is_file():
        raise FileError("Not a file")
    if f.stat().st_size > config.MAX_EDIT_BYTES:
        raise FileError("File too large to edit in the browser")
    return f.read_text(errors="replace")


def write_text(root: Path, rel: str, content: str, owner: str) -> None:
    f = safe_path(root, rel)
    if f == root.resolve() or f.is_dir():
        raise FileError("Not a file")
    f.write_text(content.replace("\r\n", "\n"))
    chown(f, owner)


def _clean_name(name: str) -> str:
    name = os.path.basename((name or "").replace("\\", "/")).strip()
    if name in ("", ".", "..") or "\x00" in name:
        raise FileError("Invalid name")
    return name


def save_upload(root: Path, rel_dir: str, filename: str, stream, owner: str) -> str:
    d = safe_path(root, rel_dir)
    if not d.is_dir():
        raise FileError("Upload target is not a folder")
    target = safe_path(root, relpath(root, d / _clean_name(filename)))
    written = 0
    with open(target, "wb") as out:
        while chunk := stream.read(1024 * 1024):
            written += len(chunk)
            if written > config.MAX_UPLOAD_BYTES:
                out.close()
                target.unlink(missing_ok=True)
                raise FileError("File exceeds the upload limit")
            out.write(chunk)
    chown(target, owner)
    return target.name


def mkdir(root: Path, rel_dir: str, name: str, owner: str) -> None:
    d = safe_path(root, rel_dir)
    target = safe_path(root, relpath(root, d / _clean_name(name)))
    target.mkdir(exist_ok=False)
    chown(target, owner)


def new_file(root: Path, rel_dir: str, name: str, owner: str) -> str:
    d = safe_path(root, rel_dir)
    target = safe_path(root, relpath(root, d / _clean_name(name)))
    if target.exists():
        raise FileError("A file with that name already exists")
    target.touch()
    chown(target, owner)
    return relpath(root, target)


def rename(root: Path, rel: str, new_name: str) -> None:
    src = safe_path(root, rel)
    if src == root.resolve():
        raise FileError("Cannot rename the site folder")
    dst = safe_path(root, relpath(root, src.parent / _clean_name(new_name)))
    if dst.exists():
        raise FileError("Target already exists")
    src.rename(dst)


PROTECTED = {"", "public", "logs", "tmp"}


def delete(root: Path, rel: str) -> None:
    target = safe_path(root, rel)
    if relpath(root, target) in PROTECTED:
        raise FileError("This folder is required and can't be deleted")
    if target.is_dir():
        shutil.rmtree(target)
    else:
        target.unlink()


def breadcrumbs(rel: str):
    crumbs, acc = [], []
    for part in [x for x in (rel or "").split("/") if x]:
        acc.append(part)
        crumbs.append((part, "/".join(acc)))
    return crumbs
