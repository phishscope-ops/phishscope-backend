# PhishScope Backend

باك إند FastAPI كامل لتطبيق PhishScope: فحص URL / Email / SMS / QR بأدلة من مصادر متعددة،
Risk Score وVerdict، كل الـ APIs المجانية، ومغطي متطلبات الأمان الـ 26.

## التشغيل (أسهل طريق: Docker)

```bash
cp .env.example .env        # واملأ المفاتيح المجانية (أو سيبها فاضية عادي)
cp ../phishscope-schema.sql ./phishscope-schema.sql   # لو مش موجود جنب الـ compose
docker compose up --build
```

- الـ API: http://localhost:8000 — التوثيق التفاعلي (Swagger): http://localhost:8000/docs
- n8n: http://localhost:5678 (admin / اللي في .env)
- PostgreSQL على 5432 والـ schema بيتطبق تلقائياً من phishscope-schema.sql

## التشغيل من غير Docker (تطوير سريع)

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
# سيب DATABASE_URL في .env على sqlite (الافتراضي)
uvicorn app.main:app --reload
```

على الموبايل أثناء التطوير: شغّل الـ backend على اللابتوب، ومن Android Emulator العنوان
`http://10.0.2.2:8000`، ومن موبايل حقيقي على نفس الشبكة `http://<IP-اللابتوب>:8000`.

## تجربة سريعة (من /docs أو curl)

```bash
# 1) تسجيل
curl -X POST localhost:8000/api/auth/register -H 'Content-Type: application/json' \
  -d '{"email":"test@phishscope.app","password":"strong-pass-123"}'
# 2) فحص لينك (خد access_token من الرد)
TOKEN=...
curl -X POST localhost:8000/api/analyze -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d '{"content":"http://paypal-secure-verify.xyz/login"}'
# 3) النتيجة
curl localhost:8000/api/analyses/<analysis_id> -H "Authorization: Bearer $TOKEN"
```

من غير أي مفاتيح: الـ static analysis + DNS/RDAP + الـ Security Engine شغالين بالكامل،
ومزودي الـ Threat Intelligence بيسجلوا `unavailable` ومحدش بيعتبر الرابط آمن بسبب كده.
مع المفاتيح المجانية بتشتغل PhishTank وURLhaus وSafe Browsing وurlscan وVirusTotal بالترتيب،
مع كاش 24 ساعة يحمي الكوتا.

## هيكل الكود

| المسار | الدور |
|--------|-------|
| `app/api/` | auth (تسجيل/دخول/خروج/refresh) + analyze + history + dashboard + inbox + devices |
| `app/analysis/` | classifier + normalize/defang + URL features + DNS/RDAP + SMS + email headers + QR |
| `app/intel/` | الـ 5 providers المجانية + كاش TTL |
| `app/engine/` | pipeline + risk/severity/verdict + ml_client (model_registry) |
| `app/models.py` | كل الجداول (مرآة phishscope-schema.sql) |
| `app/core/` | config + security (Argon2id + JWT + lockout) + logging مع redaction + RLS context |

## قرارات أمان أساسية

- السيرفر مبيفتحش اللينكات أبداً (SSRF) — التحليل كله metadata.
- عناوين IP الخاصة والداخلية مرفوضة في الإدخال وفي نتيجة الـ DNS.
- كلمات السر Argon2id + قفل الحساب 15 دقيقة بعد 5 محاولات فاشلة.
- كل IOC يتخزن ويتعرض Defanged (hxxps://example[.]com).
- الـ audit_log والـ evidence append-only على PostgreSQL (triggers تمنع التعديل).
- RLS: كل مستخدم يشوف فحوصاته بس، والـ analyst/admin استثناء.
- مفيش مفاتيح ولا لينكات ولا محتوى رسايل في اللوجز (redaction).
- Rate limiting على /api/analyze (افتراضي 30/دقيقة لكل IP).

## الـ Verdicts والألوان

SAFE/LOW_RISK أخضر · SUSPICIOUS أصفر · HIGH_RISK/MALICIOUS أحمر · INSUFFICIENT_DATA بنفسجي
