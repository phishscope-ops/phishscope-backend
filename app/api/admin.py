"""Owner-only admin overview. Disabled (404) unless ADMIN_TOKEN is set. Read-only."""
import hmac
import os
import time
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models import Analysis, AuditLog, User, UserSession

router = APIRouter(tags=["admin"])
_fails: dict[str, list[float]] = {}


def _check(request: Request) -> None:
    token = os.environ.get("ADMIN_TOKEN", "")
    if len(token) < 24:
        raise HTTPException(404, "Not Found")
    xff = request.headers.get("x-forwarded-for", "").split(",")[0].strip()
    ip = xff or (request.client.host if request.client else "?")
    now = time.time()
    recent = [t for t in _fails.get(ip, []) if now - t < 900]
    if len(recent) >= 10:
        raise HTTPException(429, "Too many attempts")
    given = request.headers.get("x-admin-token", "")
    if not hmac.compare_digest(given.encode(), token.encode()):
        recent.append(now)
        _fails[ip] = recent
        raise HTTPException(401, "Unauthorized")


def _iso(d):
    return d.isoformat() if d else None


@router.get("/api/admin/overview")
def overview(request: Request, db: Session = Depends(get_db)):
    _check(request)
    now = datetime.now(timezone.utc)
    users = db.execute(select(User).order_by(User.created_at.desc())).scalars().all()
    counts = dict(db.execute(select(Analysis.user_id, func.count()).group_by(Analysis.user_id)).all())
    since = now - timedelta(days=14)
    signups = db.execute(select(func.date(User.created_at), func.count()).where(User.created_at >= since)
                         .group_by(func.date(User.created_at)).order_by(func.date(User.created_at))).all()
    scans = db.execute(select(func.date(Analysis.created_at), func.count()).where(Analysis.created_at >= since)
                       .group_by(func.date(Analysis.created_at)).order_by(func.date(Analysis.created_at))).all()
    events = db.execute(select(AuditLog).where(AuditLog.action.in_(
        ["register", "login_success", "login_failed", "login_failed_unknown", "account_locked"]))
        .order_by(AuditLog.created_at.desc()).limit(100)).scalars().all()
    emails = {u.id: u.email for u in users}
    ips = db.execute(select(UserSession.ip, func.count(), func.max(UserSession.created_at))
                     .group_by(UserSession.ip).order_by(func.count().desc()).limit(15)).all()
    failed24 = db.execute(select(func.count()).select_from(AuditLog).where(
        AuditLog.action.in_(["login_failed", "login_failed_unknown"]),
        AuditLog.created_at >= now - timedelta(hours=24))).scalar()
    return {
        "generated_at": _iso(now),
        "totals": {"users": len(users), "analyses": sum(counts.values()),
                   "failed_logins_24h": failed24,
                   "never_logged_in": sum(1 for u in users if not u.last_login_at)},
        "signups_per_day": [[str(d), c] for d, c in signups],
        "scans_per_day": [[str(d), c] for d, c in scans],
        "users": [{"email": u.email, "name": u.full_name, "role": u.role.value, "active": u.is_active,
                   "created_at": _iso(u.created_at), "last_login_at": _iso(u.last_login_at),
                   "scans": counts.get(u.id, 0)} for u in users],
        "events": [{"at": _iso(e.created_at), "action": e.action, "email": emails.get(e.user_id) if e.user_id else (e.metadata_ or {}).get("email_masked"),
                    "ip": e.ip} for e in events],
        "top_ips": [{"ip": i, "sessions": c, "last": _iso(m)} for i, c, m in ips],
    }


PAGE = """<!doctype html><html lang="ar" dir="rtl"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>PhishScope Admin</title><style>body{font-family:system-ui;background:#0d1117;color:#e6edf3;margin:16px}input,button{padding:10px;font-size:16px}
table{border-collapse:collapse;width:100%;margin:8px 0 20px;font-size:13px}td,th{border:1px solid #30363d;padding:5px;text-align:start}
.k{display:inline-block;background:#161b22;border-radius:8px;padding:10px 14px;margin:4px}h3{color:#58a6ff}.w{color:#f85149}</style>
<h2>لوحة PhishScope (للمالك فقط)</h2><input id=t type=password placeholder="Admin token" autocomplete=off><button onclick=go()>دخول</button>
<div id=o></div><script>
function esc(s){return String(s==null?'':s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]))}
function tb(h,r){return '<table><tr>'+h.map(x=>'<th>'+x+'</th>').join('')+'</tr>'+r.map(x=>'<tr>'+x.map(y=>'<td>'+esc(y)+'</td>').join('')+'</tr>').join('')+'</table>'}
async function go(){const r=await fetch('/api/admin/overview',{headers:{'X-Admin-Token':document.getElementById('t').value}});
if(!r.ok){document.getElementById('o').innerHTML='<p class=w>مرفوض ('+r.status+')</p>';return}
const d=await r.json(),t=d.totals;let h='';
h+='<p><span class=k>مستخدمين: '+t.users+'</span><span class=k>فحوصات: '+t.analyses+'</span><span class=k>محاولات دخول فاشلة 24س: '+t.failed_logins_24h+'</span><span class=k>مسجلين ومادخلوش: '+t.never_logged_in+'</span></p>';
h+='<h3>تسجيلات جديدة (14 يوم)</h3>'+tb(['اليوم','العدد'],d.signups_per_day);
h+='<h3>فحوصات (14 يوم)</h3>'+tb(['اليوم','العدد'],d.scans_per_day);
h+='<h3>المستخدمين</h3>'+tb(['الايميل','الاسم','دور','تسجيل','آخر دخول','فحوصات'],d.users.map(u=>[u.email,u.name,u.role,u.created_at,u.last_login_at,u.scans]));
h+='<h3>آخر الأحداث</h3>'+tb(['وقت','حدث','ايميل','IP'],d.events.map(e=>[e.at,e.action,e.email,e.ip]));
h+='<h3>IP</h3>'+tb(['IP','جلسات','آخر'],d.top_ips.map(i=>[i.ip,i.sessions,i.last]));
document.getElementById('o').innerHTML=h}</script></html>"""


@router.get("/admin", response_class=HTMLResponse, include_in_schema=False)
def admin_page(request: Request):
    if len(os.environ.get("ADMIN_TOKEN", "")) < 24:
        raise HTTPException(404, "Not Found")
    return HTMLResponse(PAGE, headers={"Cache-Control": "no-store"})
