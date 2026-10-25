# Link Monitor — Desktop (Windows)

نفس فكرة نسخة الأندرويد: ألصق اللينك واضغط Start، والبرنامج بيفحص الموقع كل جولة في متصفح نضيف ويحسب الـ Uptime.

## التشغيل
نزّل `LinkMonitor-x.y.z.exe` من GitHub Actions (build-desktop > Artifacts) وشغّله على طول. مش محتاج تسطيب ولا صلاحيات أدمن.

## مصادر الـ IP
- **مباشر**: النت بتاعك.
- **VPN (ملفات WireGuard من Proton)**: «استيراد VPN» واختار ملفات `.conf`. البرنامج بيشغّلها جوّاه بس عن طريق wireproxy، ولو البورت مقفول بيجرب بورتات Proton التانية.
- **Tor**: فعّل «استخدم Tor» وحط أكواد الدول (us,de,nl...). بيدخل عن طريق bridges (obfs4 + Snowflake) لأن Tor المباشر مقفول في مصر؛ أول جولة ممكن تاخد لحد 4 دقايق.

## الملفات
- السجل: `%APPDATA%\LinkMonitor\logs` وبيتصدّر CSV بزر «تصدير CSV».
- لقطات الأعطال: `Pictures\LinkMonitor`.

## للمطوّر
```
bash get-vendor.sh
npm install
npm start          # تشغيل
npm run dist       # بناء exe في dist/
```
