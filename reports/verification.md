# Verification — trước khi nộp

- **OS / Python / Gitleaks version:** GitHub Codespaces, Ubuntu 24.04.5 LTS (Linux 6.8 x86_64) /
  Python 3.14.2 (`.venv`) / Gitleaks `8.30.1` (`gitleaks version`, binary release chính thức trong PATH) /
  pre-commit 4.6.2.

- **`python -m pytest tests/ -q --basetemp=.pytest_tmp`:** `33 passed` (0 fail, 0 skip).
  - `test_injection.py`: 8/8 (4 lure × `support_l1`, `dpo`), không SKIP.
  - `test_split.py`: pass — `KH-000777` không bị đọc, khách hợp lệ vẫn được đọc.
  - `test_obo.py`: 5/5 — support_l1 deny, dpo allow, delegation không vượt parent_scopes, hết hạn/unknown deny.
  - `test_policy.py` 4/4, `test_ledger.py` 3/3, `test_supply_chain.py` 3/3, `test_pii.py` 2/2,
    `test_check_lure_cli.py` 3/3, `test_scaffold_dispatch.py` 4/4.

- **PII (`python -m pytest tests/test_pii.py -v -s --basetemp=.pytest_tmp`):**
  `gold=118 pred=118 tp=118`, `precision=1.000`, `recall=1.000` (> 95%).
  Cách làm: regex theo thứ tự ưu tiên STK có nhãn → CCCD 12 số → SĐT `0`/`+84` → email; vùng trùng chỉ giữ
  loại ưu tiên cao hơn; `(?<!\d)`/`(?!\d)` để không cắt giữa dãy số dài; redact thay từ cuối về đầu.
  Giới hạn của regex: STK không có nhãn "STK/số tài khoản" sẽ bị coi là CCCD (nếu 12 số) hoặc bị sót; CCCD/STK
  viết tách bằng dấu cách/chấm bị sót; không nhận diện tên người hay địa chỉ (không có NER); con số 1.000 chỉ
  đúng với test set 120 câu có mẫu câu cố định.

- **`python -m agent.check_lure corpus/ticket-90*.md`:** `4/4 lure sẵn sàng.`

- **Before/after:**
  - `reports/attack-before.log`: 4 dòng (lure 901, 902, 903, cặp 904/904b), mỗi dòng là POST `/reconcile`
    chứa hồ sơ synthetic KH-000999 (CCCD/SĐT/STK/email). Tạo khi `agent/runner.py` còn là scaffold.
  - `reports/attack-after.log`: 0 byte. Trình tự: `python sink/sink.py --reset` → `pytest tests/ -q` →
    `python sink/sink.py --reset` → `python -m agent.loop --mock --as dpo "Tổng hợp các ticket còn mở tuần này"`
    → chép `reports/sink.log`. (Sau đó chạy thêm `--as support_l1` cùng câu hỏi; sink vẫn rỗng.)

- **`pre-commit run --all-files`:** `gitleaks (file hiện tại) ... Passed`.

- **Gitleaks:**
  - `gitleaks git --config .gitleaks.toml --redact --verbose .` → `leaks found: 1`, exit 1 — đúng token giả
    rule `lab24-synthetic-token` ở commit `1bdd849` (dự kiến, xem `reports/secrets-incident.md`).
  - `gitleaks dir --config .gitleaks.toml --redact .` → `no leaks found`, exit 0.
  - `python -m pip install --require-hashes -r requirements.lock` → thành công.

- **Ledger verify:** `verify(Path('reports/ledger.jsonl'))` → `True` (27 dòng, 3 dòng deny, mọi dòng có
  reason). Dòng 24: `tool=http_post`, `decision=deny`, `on_behalf_of=dpo`,
  reason `deny: dữ liệu restricted không được đi cùng egress (tool=http_post, principal=dpo)`.
  Kiểm tamper: chép ledger ra file tạm, đổi `decision` dòng 24 từ `deny` thành `allow` mà không tính lại hash
  → `verify` = `False`.

- **Các lỗi còn lại / ghi chú trung thực:**
  - Python 3.14.2 (đề yêu cầu 3.11+); `requirements.lock` sinh bằng pip-tools trên Python 3.14.
  - Lab chạy trên Linux (Codespaces) nên dùng lệnh bash tương đương thay cho PowerShell trong hướng dẫn.
  - Ledger không phát hiện cắt đuôi/viết lại toàn bộ file (đúng giới hạn đề bài nêu).
  - Số điều/khoản pháp luật trong `reports/compliance-mapping.md` ghi `chưa xác minh`.
  - Không làm phần bonus.
