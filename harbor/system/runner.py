"""Single choke point for running system commands.

Commands are always passed as argument lists (never through a shell), so user
input can never be interpreted as shell syntax.
"""
import logging
import os
import shlex
import shutil
import subprocess

from .. import config

log = logging.getLogger("harbor")
DRY_LOG: list[str] = []


class CommandError(Exception):
    pass


def run(cmd: list[str], input: str | None = None, check: bool = True, timeout: int = 300) -> str:
    if config.DRY_RUN:
        line = shlex.join(cmd)
        DRY_LOG.append(line + (f" <<< {input}" if input else ""))
        log.info("[dry-run] %s", line)
        return ""
    try:
        res = subprocess.run(cmd, input=input, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        raise CommandError(f"Command not found: {cmd[0]}")
    except subprocess.TimeoutExpired:
        raise CommandError(f"{cmd[0]} timed out")
    if check and res.returncode != 0:
        msg = (res.stderr or res.stdout or "").strip()
        raise CommandError(f"{cmd[0]} failed: {msg[:800]}")
    return res.stdout


def run_to_file(cmd: list[str], out_path) -> None:
    """Run a command and stream stdout into a file (used for mysqldump)."""
    if config.DRY_RUN:
        DRY_LOG.append(shlex.join(cmd) + f" > {out_path}")
        with open(out_path, "w") as f:
            f.write("-- dry-run dump\n")
        return
    with open(out_path, "wb") as f:
        res = subprocess.run(cmd, stdout=f, stderr=subprocess.PIPE, timeout=3600)
    if res.returncode != 0:
        raise CommandError(f"{cmd[0]} failed: {res.stderr.decode(errors='replace')[:800]}")


def run_from_file(cmd: list[str], in_path) -> None:
    """Run a command with a file on stdin (used to import SQL dumps)."""
    if config.DRY_RUN:
        DRY_LOG.append(shlex.join(cmd) + f" < {in_path}")
        return
    with open(in_path, "rb") as f:
        res = subprocess.run(cmd, stdin=f, capture_output=True, timeout=3600)
    if res.returncode != 0:
        raise CommandError(f"{cmd[0]} failed: {res.stderr.decode(errors='replace')[:800]}")


def chown(path, user: str, group: str | None = None) -> None:
    if config.DRY_RUN:
        return
    shutil.chown(path, user=user, group=group or user)


def chown_recursive(path, user: str, group: str | None = None) -> None:
    run(["chown", "-R", f"{user}:{group or user}", str(path)])


def chmod(path, mode: int) -> None:
    os.chmod(path, mode)
