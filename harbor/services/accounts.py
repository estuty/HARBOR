"""Team users and API tokens."""
from .. import auth, db, validators
from . import OpError


def create_user(username: str, password: str, role: str, site_ids: list[int], actor: str) -> int:
    username = validators.username(username)
    if role not in ("admin", "user"):
        raise OpError("Unknown role")
    if db.one("SELECT id FROM users WHERE username = ?", username):
        raise OpError(f"User {username} already exists")
    uid = auth.create_user(username, validators.password(password, min_len=12), role)
    set_sites(uid, site_ids)
    db.log(f"Created {'admin' if role == 'admin' else 'team user'} {username}", actor)
    return uid


def set_sites(user_id: int, site_ids: list[int]) -> None:
    valid = {r["id"] for r in db.all("SELECT id FROM sites")}
    with db.tx() as c:
        c.execute("DELETE FROM user_sites WHERE user_id = ?", (user_id,))
        c.executemany("INSERT INTO user_sites (user_id, site_id) VALUES (?, ?)",
                      [(user_id, s) for s in set(site_ids) if s in valid])


def update_user(user_id: int, role: str, site_ids: list[int], actor_uid: int, actor: str) -> None:
    u = db.one("SELECT * FROM users WHERE id = ?", user_id)
    if not u:
        raise OpError("User not found")
    if role not in ("admin", "user"):
        raise OpError("Unknown role")
    if user_id == actor_uid and role != "admin":
        raise OpError("You can't remove your own admin role")
    if u["role"] == "admin" and role != "admin" and \
            db.one("SELECT COUNT(*) c FROM users WHERE role = 'admin'")["c"] <= 1:
        raise OpError("At least one admin must remain")
    db.execute("UPDATE users SET role = ? WHERE id = ?", role, user_id)
    set_sites(user_id, site_ids)
    db.log(f"Updated access for {u['username']}", actor)


def set_password(user_id: int, password: str, actor: str) -> None:
    u = db.one("SELECT * FROM users WHERE id = ?", user_id)
    if not u:
        raise OpError("User not found")
    db.execute("UPDATE users SET password_hash = ? WHERE id = ?",
               auth.hash_password(validators.password(password, min_len=12)), user_id)
    db.log(f"Changed password for {u['username']}", actor)


def delete_user(user_id: int, actor_uid: int, actor: str) -> None:
    u = db.one("SELECT * FROM users WHERE id = ?", user_id)
    if not u:
        raise OpError("User not found")
    if user_id == actor_uid:
        raise OpError("You can't delete your own account")
    if u["role"] == "admin" and db.one("SELECT COUNT(*) c FROM users WHERE role = 'admin'")["c"] <= 1:
        raise OpError("At least one admin must remain")
    db.execute("DELETE FROM users WHERE id = ?", user_id)
    db.log(f"Deleted user {u['username']}", actor)


def create_token(user_id: int, name: str, actor: str) -> str:
    name = validators.single_line(name, "Token name", 60) or "API token"
    token = auth.create_token(user_id, name)
    db.log(f"Created API token '{name}'", actor)
    return token


def revoke_token(user_id: int, token_id: int, is_admin: bool, actor: str) -> None:
    row = db.one("SELECT * FROM api_tokens WHERE id = ?", token_id)
    if not row or (row["user_id"] != user_id and not is_admin):
        raise OpError("Token not found")
    db.execute("DELETE FROM api_tokens WHERE id = ?", token_id)
    db.log(f"Revoked API token '{row['name']}'", actor)
