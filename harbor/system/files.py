"""File manager confined to a site's folder.

The panel runs as root, so every path is fully resolved (following symlinks)
and must stay inside the site root; a symlink pointing outside is refused."""
import os
import shutil
import tarfile
import zipfile
from datetime import datetime
from pathlib import Path

from .. import config
from .runner import chown, chown_recursive

TEXT_EXT = {".php", ".html", ".htm", ".css", ".js", ".json", ".txt", ".md", ".xml", ".svg", ".ini",
            ".conf", ".htaccess", ".env", ".yml", ".yaml", ".sql", ".csv", ".log", ".py", ".sh", ".ts", ".twig"}
# Archive suffixes Harbor's file manager can extract, longest first so .tar.gz beats .gz.
ARCHIVE_EXT = (".tar.gz", ".tar.bz2", ".tar.xz", ".tgz", ".tbz2", ".tbz", ".txz", ".tar", ".zip")
MAX_EXTRACT_FILES = 20000
MAX_EXTRACT_BYTES = 2 * 1024 * 1024 * 1024   # cap on total uncompressed size (zip-bomb guard)


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
            "is_archive": not (e.is_dir() and not e.is_symlink()) and is_archive(e.name),
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


def is_archive(name: str) -> bool:
    return name.lower().endswith(ARCHIVE_EXT)


def extract(root: Path, rel: str, owner: str, max_bytes: int = MAX_EXTRACT_BYTES) -> int:
    """Unpack a .zip or .tar(.gz/.bz2/.xz) into the folder it sits in (like cPanel's Extract).

    The panel runs as root and the archive is untrusted, so every entry's destination is resolved
    and confirmed to stay inside the site folder (no absolute paths, no `..`, no symlink escape), and
    symlinks and device/special entries are skipped. Total uncompressed size and file count are
    capped to stop a zip bomb. Extracted files are given to the site's user."""
    root_r = root.resolve()
    src = safe_path(root, rel)
    if not src.is_file():
        raise FileError("Not a file")
    if not is_archive(src.name):
        raise FileError("Harbor can extract .zip, .tar, .tar.gz, .tgz, .tar.bz2 and .tar.xz files.")
    dest = src.parent

    def dest_for(member: str) -> Path:
        name = (member or "").replace("\\", "/").strip("/")
        if not name:
            return None
        if any(part in ("", "..") for part in name.split("/")):
            raise FileError(f"The archive has an unsafe path and wasn't extracted: {member}")
        p = (dest / name).resolve()
        if p != root_r and root_r not in p.parents:
            raise FileError("The archive would write outside the site folder, so nothing was extracted.")
        return p

    tops: set = set()

    def place(member: str):
        """Resolve a member to its destination, record its top-level entry for chown, return the path."""
        p = dest_for(member)
        if p is not None and p != dest:
            tops.add(dest / p.relative_to(dest).parts[0])
        return p

    try:
        if src.name.lower().endswith(".zip"):
            count = _extract_zip(src, place, max_bytes)
        else:
            count = _extract_tar(src, place, max_bytes)
    except (zipfile.BadZipFile, tarfile.TarError, EOFError) as e:
        raise FileError(f"The archive is damaged or unreadable: {e}")
    for top in tops:
        if top.exists():
            chown_recursive(top, owner)
    return count


def _guard(total: int, files: int, max_bytes: int) -> None:
    if files > MAX_EXTRACT_FILES:
        raise FileError(f"The archive holds more than {MAX_EXTRACT_FILES:,} files; extract it over SSH instead.")
    if total > max_bytes:
        raise FileError(f"The extracted files would total {total // (1024 * 1024)} MB, over the "
                        f"{max_bytes // (1024 * 1024)} MB limit — extract it over SSH, or raise the site's disk allowance.")


def _extract_zip(src: Path, place, max_bytes: int) -> int:
    count = 0
    with zipfile.ZipFile(src) as z:
        infos = z.infolist()
        _guard(sum(i.file_size for i in infos), len(infos), max_bytes)
        for i in infos:
            p = place(i.filename)
            if p is None:
                continue
            if i.is_dir():
                p.mkdir(parents=True, exist_ok=True)
            else:
                p.parent.mkdir(parents=True, exist_ok=True)
                with z.open(i) as fsrc, open(p, "wb") as out:
                    shutil.copyfileobj(fsrc, out, 1024 * 1024)
                count += 1
    return count


def _extract_tar(src: Path, place, max_bytes: int) -> int:
    count = 0
    with tarfile.open(src) as t:
        members = t.getmembers()
        _guard(sum(m.size for m in members if m.isreg()), len(members), max_bytes)
        for m in members:
            if m.issym() or m.islnk() or m.isdev() or m.ischr() or m.isblk() or m.isfifo():
                continue        # never recreate links or special files from an untrusted archive
            p = place(m.name)
            if p is None:
                continue
            if m.isdir():
                p.mkdir(parents=True, exist_ok=True)
            elif m.isreg():
                p.parent.mkdir(parents=True, exist_ok=True)
                fsrc = t.extractfile(m)
                if fsrc is None:
                    continue
                with fsrc, open(p, "wb") as out:
                    shutil.copyfileobj(fsrc, out, 1024 * 1024)
                count += 1
    return count


def breadcrumbs(rel: str):
    crumbs, acc = [], []
    for part in [x for x in (rel or "").split("/") if x]:
        acc.append(part)
        crumbs.append((part, "/".join(acc)))
    return crumbs
