"""Git deploy, low level.

Everything runs as the site's own Linux user, inside the site folder:

    /srv/harbor/sites/<domain>/git/repo     working copy (fetched branch, build happens here)
    /srv/harbor/sites/<domain>/git/.ssh     the site's deploy key and known_hosts

A deploy fetches the branch, checks out one commit, runs the optional build,
then copies the result into public/ with rsync, keeping the paths the user
listed (uploads, .env, …). Nothing touches public/ until the build succeeded."""
import shlex
import subprocess
import threading
from pathlib import Path

from .. import config
from .runner import DRY_LOG, CommandError, chown, run

PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
DRY_SHA = "d" * 40


def git_dir(root: Path) -> Path:
    return root / "git"


def repo_dir(root: Path) -> Path:
    return git_dir(root) / "repo"


def ssh_dir(root: Path) -> Path:
    return git_dir(root) / ".ssh"


def key_file(root: Path) -> Path:
    return ssh_dir(root) / "id_ed25519"


def prepare(root: Path, sysuser: str) -> None:
    for d in (git_dir(root), ssh_dir(root)):
        d.mkdir(parents=True, exist_ok=True)
        d.chmod(0o700)
        chown(d, sysuser)


def _env(root: Path) -> list[str]:
    ssh = (f"ssh -i {key_file(root)} -o IdentitiesOnly=yes -o BatchMode=yes -o ConnectTimeout=20 "
           f"-o StrictHostKeyChecking=accept-new -o UserKnownHostsFile={ssh_dir(root)}/known_hosts")
    return [f"HOME={root}/tmp", f"PATH={PATH}", "LANG=C.UTF-8", "GIT_TERMINAL_PROMPT=0",
            f"GIT_SSH_COMMAND={ssh}", "GIT_CONFIG_NOSYSTEM=1"]


def as_site(sysuser: str, root: Path, args: list[str], cwd: Path | None = None) -> list[str]:
    """Command line that runs `args` as the site user with a clean environment."""
    return ["runuser", "-u", sysuser, "--", "env", "-i"] + (["-C", str(cwd)] if cwd else []) + _env(root) + args


def stream(cmd: list[str], log, timeout: int = 900, max_lines: int = 400) -> str:
    """Run a command, sending its output to `log` line by line. Raises CommandError
    (with the last lines of output) if it fails or runs too long."""
    if config.DRY_RUN:
        DRY_LOG.append(shlex.join(cmd))
        return ""
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, errors="replace")
    killed = threading.Event()

    def kill():
        killed.set()
        proc.kill()
    timer = threading.Timer(timeout, kill)
    timer.start()
    tail: list[str] = []
    shown = 0
    try:
        for line in proc.stdout:
            line = line.rstrip()[:500]
            tail = (tail + [line])[-30:]
            shown += 1
            if shown <= max_lines:
                log("    " + line)
            elif shown == max_lines + 1:
                log("    … (more output not shown)")
        proc.wait()
    finally:
        timer.cancel()
    if killed.is_set():
        raise CommandError(f"stopped after {timeout // 60} minutes")
    if proc.returncode != 0:
        raise CommandError(f"exited with code {proc.returncode}")
    return "\n".join(tail)


# ---------------------------------------------------------------- deploy key

def ensure_key(root: Path, sysuser: str, comment: str) -> str:
    prepare(root, sysuser)
    k = key_file(root)
    if config.DRY_RUN:
        if not k.exists():
            k.write_text("dry-run private key\n")
            k.with_suffix(".pub").write_text(f"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDRYRUNkcnlydW4ga2V5 {comment}\n")
        return public_key(root)
    if not k.exists():
        run(as_site(sysuser, root, ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", comment, "-f", str(k)]))
    return public_key(root)


def rotate_key(root: Path, sysuser: str, comment: str) -> str:
    for f in (key_file(root), key_file(root).with_suffix(".pub"), ssh_dir(root) / "known_hosts"):
        f.unlink(missing_ok=True)
    return ensure_key(root, sysuser, comment)


def public_key(root: Path) -> str:
    pub = key_file(root).with_suffix(".pub")
    return pub.read_text().strip() if pub.exists() else ""


# ---------------------------------------------------------------- git

def ls_remote(root: Path, sysuser: str, url: str) -> list[str]:
    """Branches on the remote. Raises CommandError with git's message if it can't connect."""
    if config.DRY_RUN:
        DRY_LOG.append(f"git ls-remote --heads {url}")
        return ["main"]
    try:
        out = run(as_site(sysuser, root, ["git", "ls-remote", "--heads", "--", url]), timeout=60)
    except CommandError as e:
        raise CommandError(_explain(str(e)))
    return sorted(line.split("refs/heads/", 1)[1] for line in out.splitlines() if "refs/heads/" in line)


def _explain(msg: str) -> str:
    low = msg.lower()
    if "connection refused" in low or "no route to host" in low or "network is unreachable" in low \
            or "connection timed out" in low:
        return "Couldn't reach the repository's server (" + next(
            (w for w in ("connection refused", "no route to host", "network is unreachable", "connection timed out")
             if w in low)) + "). Check the address and port."
    if "host key verification failed" in low:
        return ("The repository server's SSH host key changed since the first connection. If that's expected, "
                "create a new deploy key here (that also resets the saved host key).")
    if "permission denied (publickey)" in low or "could not read from remote" in low:
        return ("The repository refused the deploy key. Add the key below to the repository "
                "(GitHub: Settings → Deploy keys → Add deploy key), or use the https address for a public repository.")
    if "couldn't find remote ref" in low:
        return "That branch doesn't exist in the repository (or has no commits yet)."
    if "could not resolve host" in low:
        return "The repository's host name couldn't be found. Check the address."
    if "repository not found" in low or "not found" in low:
        return ("Repository not found. Check the address; if it's private, use the SSH address "
                "(git@github.com:owner/repo.git) with the deploy key.")
    if "authentication failed" in low or "terminal prompts disabled" in low:
        return "This repository needs a login. Use its SSH address (git@…) and add the deploy key below."
    if "timed out" in low:
        return "The repository host didn't answer in time."
    return msg.replace("git failed: ", "")


def fetch(root: Path, sysuser: str, url: str, branch: str, log) -> str:
    """Fetch the branch into the working copy; returns the commit it points to."""
    repo = repo_dir(root)
    if config.DRY_RUN:
        repo.mkdir(parents=True, exist_ok=True)
        DRY_LOG.append(f"git fetch {url} {branch}")
        return DRY_SHA
    prepare(root, sysuser)
    if not (repo / ".git").exists():
        repo.mkdir(exist_ok=True)
        chown(repo, sysuser)
        run(as_site(sysuser, root, ["git", "init", "-q", str(repo)]))
    try:
        stream(as_site(sysuser, root, ["git", "-C", str(repo), "fetch", "--prune", "--no-tags", "--progress",
                                       "--", url, f"+refs/heads/{branch}:refs/remotes/origin/{branch}"]),
               log, timeout=900, max_lines=40)
    except CommandError as e:
        recent = " ".join(_last_lines(log))
        hint = _explain(recent)
        raise CommandError(f"Fetching {branch} failed ({e})." + (f" {hint}" if hint != recent else ""))
    return run(as_site(sysuser, root, ["git", "-C", str(repo), "rev-parse", f"refs/remotes/origin/{branch}"])).strip()


def _last_lines(log) -> list[str]:
    return getattr(log, "lines", [])[-5:]


def has_commit(root: Path, sysuser: str, sha: str) -> bool:
    if config.DRY_RUN:
        return True
    try:
        run(as_site(sysuser, root, ["git", "-C", str(repo_dir(root)), "cat-file", "-e", f"{sha}^{{commit}}"]))
        return True
    except CommandError:
        return False


def checkout(root: Path, sysuser: str, sha: str, log) -> dict:
    """Check out one commit (clean tree, ignored files like node_modules kept for faster builds)."""
    repo = repo_dir(root)
    if config.DRY_RUN:
        DRY_LOG.append(f"git checkout {sha}")
        return {"sha": sha, "message": "Dry-run commit", "author": "dry-run", "date": ""}
    g = lambda *a: run(as_site(sysuser, root, ["git", "-C", str(repo), *a]), timeout=600)
    g("-c", "advice.detachedHead=false", "checkout", "-q", "-f", "--detach", sha)
    g("clean", "-ffdq")
    if (repo / ".gitmodules").exists():
        log("Updating submodules…")
        stream(as_site(sysuser, root, ["git", "-C", str(repo), "submodule", "update", "--init", "--recursive"]),
               log, timeout=900, max_lines=40)
    out = g("log", "-1", "--format=%H%x1f%s%x1f%an%x1f%cI", sha).strip().split("\x1f")
    return {"sha": out[0], "message": out[1][:200], "author": out[2][:100], "date": out[3] if len(out) > 3 else ""}


def run_script(root: Path, sysuser: str, script: str, cwd: Path, log, timeout: int = 1800) -> None:
    stream(as_site(sysuser, root, ["bash", "-e", "-o", "pipefail", "-c", script], cwd=cwd), log, timeout=timeout)


def sync(root: Path, sysuser: str, subdir: str, keep: list[str], delete: bool, log) -> tuple[int, int]:
    """Copy the checked-out (and built) files into public/. Returns (updated, removed)."""
    src = repo_dir(root) / subdir if subdir else repo_dir(root)
    dest = root / "public"
    if config.DRY_RUN:
        DRY_LOG.append(f"rsync {src}/ {dest}/")
        return 0, 0
    if not src.is_dir():
        raise CommandError(f"The folder '{subdir}' isn't in the repository (after the build). "
                           "Check 'Folder to publish'.")
    args = ["rsync", "-rlpt", "--itemize-changes", "--exclude=.git", "--exclude=.git/"]
    for k in keep:
        args.append(f"--exclude=/{k}")
    if delete:
        args.append("--delete-after")
    args += [f"{src}/", f"{dest}/"]
    out = run(as_site(sysuser, root, args), timeout=3600)
    updated = sum(1 for line in out.splitlines() if line.startswith((">f", "cL")))
    removed = sum(1 for line in out.splitlines() if line.startswith("*deleting"))
    return updated, removed


def remove_checkout(root: Path) -> None:
    """Forget the working copy and key (the live files in public/ stay)."""
    if config.DRY_RUN:
        import shutil
        shutil.rmtree(git_dir(root), ignore_errors=True)
        return
    run(["rm", "-rf", "--one-file-system", str(git_dir(root))])

