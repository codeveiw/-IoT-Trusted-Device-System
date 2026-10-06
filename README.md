# 🛡️ IoT Trusted Device System (Trusted Computing Simulation)

مشروع تطبيقي يحاكي مبادئ الحوسبة الموثوقة (**Trusted Computing**) وبنية الثقة المعدومة (**Zero Trust Architecture**) في أجهزة إنترنت الأشياء (**IoT**). يقوم النظام بالتحقق الصارم من هوية الأجهزة وتكامل نظام التشغيل/البرمجيات الثابتة (**Firmware Integrity Measurement**) قبل السماح لها بالاتصال بالشبكة أو إرسال البيانات.

---

## 🏗️ البنية المعمارية للنظام (Architecture)

```
trusted_computing/
├── app/
│   ├── __init__.py
│   ├── crypto_utils.py       # دوال التشفير: SHA-256 للقياس، HMAC-SHA256 للمصادقة، وتوليد الـ Nonce
│   ├── database.py           # قاعدة بيانات SQLite للأجهزة المسجلة و Golden Hashes وسجلات التدقيق
│   ├── models.py             # مخططات Pydantic للبيانات والتحقق من صحة المدخلات
│   ├── verifier.py           # محرك التحقق من الثقة (Policy Engine) وبوابة الوصول (Gatekeeper)
│   └── main.py               # سيرفر FastAPI الرئيسي والـ Endpoints ولوحة التحكم
├── simulator/
│   ├── firmware_samples/     # عينات البرمجيات الثابتة
│   │   ├── firmware_v1.bin       # البرنامج الأصلي السليم (Genuine)
│   │   └── firmware_tampered.bin # نسخة محقونة بباكدور/تعديل خبيث (Tampered)
│   └── device_agent.py       # عميل محاكاة أجهزة الـ IoT بمختلف السيناريوهات
├── templates/
│   └── dashboard.html        # لوحة تحكم تفاعلية متطورة للمراقبة الحية واختبار الهجمات
├── requirements.txt          # مكتبات المشروع (FastAPI, Uvicorn, Pydantic, Requests)
├── run_server.py             # سكربت تشغيل السيرفر
└── README.md
```

---

## 🔐 ركائز Trusted Computing المطبقة

1. **جذر الثقة والهوية (Root of Trust & Hardware Identity)**:
   - كل جهاز يمتلك `Device ID` ومفتاح تشفير سري `Secret Key` (محاكاة لشريحة TPM أو Secure Element).
2. **القياس والتكامل (Integrity Measurement / Measured Boot)**:
   - فحص البرمجية الثابتة وحساب بصمتها التشفيرية (**SHA-256**) ومقارنتها بالبصمة الذهبية المعتمدة (**Golden Hash**).
3. **الشهادة عن بُعد ومنع هجمات الإعادة (Remote Attestation & Anti-Replay)**:
   - يتم طلب `Nonce` فريد مؤقت لكل جلسة، ويقوم الجهاز بتوقيع التحدي عبر `HMAC-SHA256`.
4. **بوابة الوصول ومبدأ الثقة المعدومة (Zero-Trust Gatekeeper)**:
   - لا يُسمح لأي جهاز بإرسال بيانات الحساسات (`/api/telemetry`) إلا إذا كان حاصلاً على حالة `TRUSTED` ومعه `Trust Token` سارٍ.

---

## ⚡ خطوات التثبيت والتشغيل (Quick Start)

### 1. تثبيت المتطلبات (Dependencies)
```bash
pip install -r requirements.txt
```

### 2. تشغيل سيرفر التحقق (Attestation Server)
```bash
python run_server.py
```
- **سيرفر التحقق**: `http://127.0.0.1:8000`
- **لوحة التحكم التفاعلية (Web Dashboard)**: `http://127.0.0.1:8000/dashboard`
- **توثيق الواجهات التفاعلي (Swagger UI)**: `http://127.0.0.1:8000/docs`

---

## 🧪 سيناريوهات المحاكاة واختبار الهجمات

يمكنك تشغيل المحاكي عبر سطر الأوامر (CLI) أو من خلال أزرار Sandbox داخل الـ Dashboard:

### تشغيل جميع السيناريوهات في المحاكي:
```bash
python simulator/device_agent.py --scenario 0
```

### تجربة سيناريو محدد:
- **السيناريو 1 (جهاز سليم - Trusted Device)**:
  ```bash
  python simulator/device_agent.py --scenario 1
  ```
  *النتيجة*: يجتاز التحقق، يُمنح `Trust Token`، ويُقبل إرسال بيانات الحساسات (`200 OK`).

- **السيناريو 2 (هجوم التلاعب بالـ Firmware - Tampered Firmware)**:
  ```bash
  python simulator/device_agent.py --scenario 2
  ```
  *النتيجة*: اختلاف الـ SHA-256 عن البصمة الذهبية -> يتم الحظر كـ `UNTRUSTED` وتُمنع بيانات الحساسات (`403 Forbidden`).

- **السيناريو 3 (جهاز مجهول / مفتاح غير صالح - Rogue Key Attack)**:
  ```bash
  python simulator/device_agent.py --scenario 3
  ```
  *النتيجة*: فشل التوقيع الرقمي (Signature Check Failed) -> يتم الحظر فوراً كـ `UNTRUSTED`.

- **السيناريو 4 (هجوم إعادة الإرسال - Replay Attack)**:
  ```bash
  python simulator/device_agent.py --scenario 4
  ```
  *النتيجة*: إعادة إرسال نفس الطلب بنفس الـ Nonce -> يكتشف النظام أن الـ Nonce مستهلك ويرفضه فوراً.

---

## 📊 لوحة التحكم (Interactive Dashboard)
افتح المتصفح على:
👉 **[http://127.0.0.1:8000/dashboard](http://127.0.0.1:8000/dashboard)**

تتيح لك:
- متابعة فورية لحالة الأجهزة (`TRUSTED` 🟢 مقابل `UNTRUSTED` 🔴).
- مراقبة سجلات التدقيق (Attestation Audit Log) وسبب رفض كل محاولة بالتفصيل.
- إمكانية سحب الثقة (Revoke) من أي جهاز يدوياً.
- منصة اختبار تفاعلية (Interactive Sandbox) لتجربة الهجمات بنقرة زر واحدة.
