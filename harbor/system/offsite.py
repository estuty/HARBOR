"""Offsite copies of backups in any S3-compatible storage: AWS S3, Backblaze B2,
DigitalOcean Spaces, Wasabi, Cloudflare R2, MinIO…"""
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .. import db

KEYS = ("offsite_endpoint", "offsite_region", "offsite_bucket", "offsite_prefix", "offsite_key", "offsite_secret")


class OffsiteError(Exception):
    pass


def settings() -> dict:
    s = {k: db.get_setting(k) for k in KEYS}
    s["offsite_auto"] = db.get_setting("offsite_auto", "1") == "1"
    s["offsite_keep_days"] = int(db.get_setting("offsite_keep_days", "30") or 0)
    return s


def configured() -> bool:
    s = settings()
    return bool(s["offsite_bucket"] and s["offsite_key"] and s["offsite_secret"])


def _client(s: dict | None = None):
    import boto3
    from botocore.config import Config
    s = s or settings()
    if not (s["offsite_bucket"] and s["offsite_key"] and s["offsite_secret"]):
        raise OffsiteError("Offsite storage isn't set up")
    return boto3.client(
        "s3",
        endpoint_url=s["offsite_endpoint"] or None,
        region_name=s["offsite_region"] or "us-east-1",
        aws_access_key_id=s["offsite_key"],
        aws_secret_access_key=s["offsite_secret"],
        config=Config(retries={"max_attempts": 4, "mode": "standard"}, connect_timeout=15, read_timeout=120,
                      s3={"addressing_style": "path" if s["offsite_endpoint"] else "auto"}),
    )


def _wrap(fn, *a, **kw):
    from botocore.exceptions import BotoCoreError, ClientError
    try:
        return fn(*a, **kw)
    except ClientError as e:
        err = e.response.get("Error", {})
        raise OffsiteError(f"{err.get('Code', 'Error')}: {err.get('Message', str(e))}")
    except BotoCoreError as e:
        raise OffsiteError(str(e))


def key_for(domain: str, filename: str) -> str:
    host = db.get_setting("hostname") or "harbor"
    prefix = (settings()["offsite_prefix"] or "harbor").strip("/")
    return f"{prefix}/{host}/{domain}/{filename}"


def test(s: dict) -> str:
    """Write, read back and delete a small object."""
    c = _client(s)
    prefix = (s["offsite_prefix"] or "harbor").strip("/")
    k = f"{prefix}/.harbor-connection-test"
    _wrap(c.put_object, Bucket=s["offsite_bucket"], Key=k, Body=b"ok")
    body = _wrap(c.get_object, Bucket=s["offsite_bucket"], Key=k)["Body"].read()
    _wrap(c.delete_object, Bucket=s["offsite_bucket"], Key=k)
    if body != b"ok":
        raise OffsiteError("Read-back check failed")
    return s["offsite_bucket"]


def upload(path: Path, key: str) -> None:
    c = _client()
    _wrap(c.upload_file, str(path), settings()["offsite_bucket"], key,
          ExtraArgs={"ContentType": "application/gzip"})


def list_for(domain: str) -> list[dict]:
    c = _client()
    s = settings()
    prefix = key_for(domain, "")
    out, token = [], None
    while True:
        kw = {"Bucket": s["offsite_bucket"], "Prefix": prefix}
        if token:
            kw["ContinuationToken"] = token
        resp = _wrap(c.list_objects_v2, **kw)
        for o in resp.get("Contents", []):
            if o["Key"].endswith(".tar.gz"):
                out.append({"key": o["Key"], "name": o["Key"].rsplit("/", 1)[-1], "size": o["Size"],
                            "modified": o["LastModified"]})
        if not resp.get("IsTruncated"):
            break
        token = resp.get("NextContinuationToken")
    return sorted(out, key=lambda o: o["modified"], reverse=True)


def download(key: str, dest: Path) -> None:
    c = _client()
    _wrap(c.download_file, settings()["offsite_bucket"], key, str(dest))


def delete(key: str) -> None:
    c = _client()
    _wrap(c.delete_object, Bucket=settings()["offsite_bucket"], Key=key)


def prune(domain: str) -> int:
    days = settings()["offsite_keep_days"]
    if days <= 0:
        return 0
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    objs = list_for(domain)
    removed = 0
    for o in objs[3:]:  # always keep the 3 newest, whatever their age
        if o["modified"] < cutoff:
            delete(o["key"])
            removed += 1
    return removed
