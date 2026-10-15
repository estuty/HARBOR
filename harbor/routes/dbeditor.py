"""nginx asks this before letting a browser into the database editor (/dbadmin/):
only someone signed in to the panel gets through."""
from fastapi import APIRouter, Request
from fastapi.responses import Response

from .. import db

router = APIRouter()


@router.get("/dbadmin-check")
async def dbadmin_check(request: Request):
    uid = request.session.get("uid")
    ok = bool(uid and db.one("SELECT 1 FROM users WHERE id = ?", uid))
    return Response(status_code=204 if ok else 401)
