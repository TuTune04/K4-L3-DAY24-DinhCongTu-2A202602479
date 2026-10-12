# DPIA-lite — checkpoint 5

Phạm vi: agent hỗ trợ khách hàng của lab Day 24, chạy `--mock` trên dữ liệu **synthetic**. Đây là đánh giá
tác động rút gọn cho môi trường lab, không phải DPIA chính thức theo pháp luật.

## 1. Loại dữ liệu và phân loại

| Dữ liệu | Nguồn | Trường | Phân loại |
|---|---|---|---|
| Ticket hỗ trợ | `corpus/*.md` (do khách/bên ngoài viết — **không tin cậy**) | text tự do, có thể chứa STK/SĐT/CCCD/email và chỉ thị injection | `internal` |
| Hồ sơ khách | `data/customers.json` (private store) | họ tên, CCCD, SĐT, STK, email, `related_tickets` | `restricted` (CCCD + STK là dữ liệu nhạy cảm) |
| Quyền giả lập | `data/principals.json` | role, allowed_tools, purposes | cấu hình tin cậy (mô phỏng) |
| Ledger | `reports/ledger.jsonl` | ai/agent/run/tool/decision/reason, `args_hash` | `internal`, **không chứa PII thô** |

## 2. Mục đích xử lý và principal

- `summarize-tickets`: tổng hợp ticket — `support_l1`, `billing`, `dpo` được `search_docs`.
- `support-reply`: đọc hồ sơ khách **gắn với ticket** để trả lời — chỉ `dpo` (có `read_customer` và purpose này).
  `billing` có `read_customer` nhưng không có purpose `support-reply` nên bị deny trong luồng này.
- Không mục đích nào cho phép gửi dữ liệu restricted ra ngoài: "đối soát" mà lure đòi hỏi không phải
  mục đích hợp lệ và luôn bị deny ở egress.
- Mỗi lần chạy có `agent_id=lab24-agent`, `run_id` riêng cho Run A / Run B / egress, `on_behalf_of` và
  `expires_at` (TTL 15 phút) — `agent/runner.py:189-196`.

## 3. Dữ liệu đi qua những run/tool nào, endpoint nào

```
user query ──► Run A: search_docs (corpus/, internal)
                 │  pii.redact() trên text  ─► llm.summarize() ─► câu trả lời CLI
                 │  find_injection() chỉ để phát hiện/cảnh báo
                 ▼  chỉ list[int] ticket_id từ TÊN FILE
               Run B: PEP read_customer (restricted)  ── support_l1: deny, dừng, không mở customers.json
                 │  dpo: tra related_tickets ─► PEP lại trước từng read_customer
                 ▼
               Egress: PEP http_post (restricted + egress=True) ── luôn deny ─► không gọi tools.http_post
                                              endpoint duy nhất có thể: http://127.0.0.1:10024 (sink lab)
```

- Hồ sơ khách đọc ở Run B chỉ dùng để in **customer_id** liên quan trong câu trả lời, không in CCCD/STK.
- Endpoint mạng duy nhất là sink localhost `127.0.0.1:10024` (allowlist cứng `agent/tools.py:76-83`);
  sau containment không có POST nào (`reports/attack-after.log` rỗng).

## 4. Bằng chứng deny/allow và giới hạn của mock

Bằng chứng:
- Trước: `reports/attack-before.log` — 4 POST chứa hồ sơ synthetic KH-000999 (CCCD `811753472374`, STK
  `9103069783`), một dòng cho mỗi lure 901–904.
- Sau: `reports/attack-after.log` rỗng; `reports/ledger.jsonl` dòng 24 `http_post` **deny** cho `dpo`,
  dòng 26 `read_customer` **deny** cho `support_l1`, dòng 27 `http_post` deny cho `support_l1`; dòng 2–23
  là `read_customer` **allow** hợp lệ của `dpo` (21 khách gắn với ticket, kèm 1 dòng cổng mở private store).
- `verify(reports/ledger.jsonl)` = `True`; sửa `decision` dòng 24 từ deny → allow trên bản sao thì `verify` = `False`.
- `pytest tests/` 33 passed (gồm 8 case injection, split KH-000777, OBO 5 case).

Rủi ro còn lại và giới hạn:
- **Mock ≠ model thật**: `find_injection` dựa trên marker; model thật có thể bị chiếm quyền theo cách khác.
  Containment không dựa vào phát hiện (Run B không đọc free text) nên kết luận vẫn đứng, nhưng chưa được kiểm
  với model thật.
- `--as` chỉ chọn fixture, không xác thực danh tính; `principals.json` có thể bị sửa bởi ai có quyền ghi repo.
- `dpo` vẫn đọc hồ sơ KH-000999 vì khách này thật sự gắn với ticket lure — rủi ro được giảm nhờ chặn egress,
  không phải nhờ split. Hồ sơ đã đọc vẫn nằm trong bộ nhớ tiến trình.
- Regex PII: precision/recall 1.000 trên test set 120 câu, nhưng sẽ sót định dạng khác (STK không có nhãn,
  số viết có dấu chấm giữa CCCD, tên người — không có NER).
- Ledger một file: không phát hiện cắt đuôi hay viết lại toàn bộ chuỗi; không có lưu trữ ngoài/WORM.
- Không có cơ chế đồng ý, thời hạn lưu trữ hay xoá dữ liệu cho chủ thể — ngoài phạm vi lab.
