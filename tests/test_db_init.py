"""The panel service and the installer may set up the database at the same moment."""
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = str(Path(__file__).resolve().parent.parent)
SCRIPT = "from harbor import db; db.init(); print(db.one('PRAGMA user_version')[0])"


def test_concurrent_init_runs_migrations_once():
    sandbox = tempfile.mkdtemp(prefix="harbor-race-")
    env = dict(os.environ, HARBOR_DRY_RUN="1", HARBOR_SANDBOX=sandbox, PYTHONPATH=ROOT)
    procs = [subprocess.Popen([sys.executable, "-c", SCRIPT], env=env, cwd=ROOT,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) for _ in range(8)]
    results = [p.communicate(timeout=120) for p in procs]
    errors = [err for _, err in results if "Error" in err]
    assert not errors, errors[0]
    from harbor import db
    assert {out.strip() for out, _ in results} == {str(len(db.MIGRATIONS))}
