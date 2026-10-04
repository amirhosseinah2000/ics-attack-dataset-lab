# راهنمای مرحله دوم Modbus — MODBUS-MANIP-001

## هدف

این مرحله یک سناریوی مستقل «دستکاری فرایند» را روی Digital Twin محلی Aloha اجرا می‌کند. هدف، تست کامل زنجیره زیر قبل از اتصال به Dashboard است:

PCAP → Process State → Ground Truth → Extraction → Packet Labeling → Validation → Restore

سناریو فقط برای Docker service محلی `aloha-plc` طراحی شده است و Runner اجازه تغییر Target به IP خارجی را نمی‌دهد.

## فایل‌های جدید

- `configs/scenarios/modbus/MODBUS-MANIP-001.yaml`
- `scripts/modbus_manual_overflow_lab.py`
- `scripts/preflight_modbus_manip_001.ps1`
- `scripts/run_modbus_manip_001.ps1`
- `scripts/validate_modbus_run.py` (نسخه به‌روزشده که Recon و Manipulation را هر دو می‌شناسد)

## پیش‌نیازهایی که باید از مرحله قبل وجود داشته باشند

- `scripts/record_process_state.ps1`
- `scripts/extract_modbus.ps1`
- `scripts/label_modbus_packets.py`
- `external/aloha-water-treatment/docker-compose-example.yml`

## 1) بررسی Git قبل از شروع

از Root پروژه:

```powershell
git status --short
```

فعلاً Commit یا Push نکن.

## 2) بالا بودن Digital Twin

اگر Aloha بالا نیست:

```powershell
docker compose -f .\external\aloha-water-treatment\docker-compose-example.yml up -d
```

سپس:

```powershell
docker compose -f .\external\aloha-water-treatment\docker-compose-example.yml ps
```

حداقل `aloha-plc` و `aloha-hmi` باید در حال اجرا باشند.

## 3) Preflight

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\preflight_modbus_manip_001.ps1
```

انتظار داریم انتهای خروجی چنین باشد:

```text
Preflight passed. The lab is ready for a short smoke run.
```

اگر Preflight شکست خورد، Runner را اجرا نکن و همان خروجی خطا را بررسی کن.

## 4) Smoke Run کوتاه

برای اولین تست از زمان‌های کوتاه استفاده کن:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\run_modbus_manip_001.ps1 `
  -WarmupSeconds 10 `
  -AttackSeconds 10 `
  -RecoverySeconds 10 `
  -InflowRate 900 `
  -OutflowRate 50
```

Runner باید پوشه‌ای مانند این بسازد:

```text
captures\modbus\attack\MODBUS-MANIP-001_YYYYMMDD_HHMMSS\
```

## 5) خروجی‌های مورد انتظار

- `traffic.pcap`
- `process_state.csv`
- `modbus_packets.csv`
- `modbus_packets_labeled.csv`
- `ground_truth.jsonl`
- `attack_stats.json`
- `label_summary.json`
- `validation_report.json`
- `manifest.yaml`
- `run.log`

## 6) معیارهای اصلی موفقیت Smoke Run

در خروجی نهایی باید این موارد را ببینیم:

- `Normal rows > 0`
- `Attack rows > 0`
- `Background@Attack > 0`
- Function Code شماره 5 در Requestهای حمله وجود داشته باشد.
- Function Code شماره 6 در Requestهای حمله وجود داشته باشد.
- سطح Tank نسبت به baseline افزایش نشان دهد.
- `Restored : True`
- `Validation : PASS`

فعال شدن Overflow Alarm برای Smoke Run اجباری نیست.

## 7) بررسی سریع Function Codeها

بعد از Run، مسیر آخرین Run را بگیر:

```powershell
$run = Get-ChildItem .\captures\modbus\attack -Directory |
  Where-Object Name -Like 'MODBUS-MANIP-001_*' |
  Sort-Object LastWriteTime -Descending |
  Select-Object -First 1

$run.FullName
```

و Distribution را ببین:

```powershell
Import-Csv "$($run.FullName)\modbus_packets_labeled.csv" |
  Group-Object 'modbus.func_code' |
  Sort-Object Count -Descending |
  Select-Object Name, Count
```

برای Attack-only:

```powershell
Import-Csv "$($run.FullName)\modbus_packets_labeled.csv" |
  Where-Object label_binary -eq 'attack' |
  Group-Object 'modbus.func_code' |
  Sort-Object Count -Descending |
  Select-Object Name, Count
```

## 8) فایل‌هایی که برای بررسی نتیجه لازم‌اند

اگر Smoke Run تمام شد، برای بررسی دقیق این سه فایل کافی‌اند:

- `validation_report.json`
- `label_summary.json`
- `attack_stats.json`

اگر Validation شکست خورد، `run.log` را هم نگه دار.

## 9) Run استاندارد

فقط بعد از PASS شدن Smoke Run:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\run_modbus_manip_001.ps1 `
  -WarmupSeconds 30 `
  -AttackSeconds 30 `
  -RecoverySeconds 30 `
  -InflowRate 900 `
  -OutflowRate 50
```

## 10) تصمیم بعد از Run استاندارد

هنوز Dashboard را تغییر نمی‌دهیم. ابتدا چند Run معتبر از همین Scenario می‌گیریم و تنوع پارامترها را بررسی می‌کنیم. بعد از تثبیت سناریو، آن را Freeze می‌کنیم و سراغ Scenario بعدی می‌رویم.
