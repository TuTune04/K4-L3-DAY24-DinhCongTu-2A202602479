# Baseline — checkpoint 1

Đọc trên code scaffold ban đầu (runner còn là stub nên `run_once()` rơi về `_naive_loop()`).
Số dòng dưới đây là số dòng trong `agent/loop.py`, `agent/tools.py`, `sink/sink.py` của repo này
(các file đó không bị sửa trong bài).

1. **Agent có identity mỗi run chưa? Dẫn file/hàm:**
   Chưa. `_naive_loop(message, llm)` ở `agent/loop.py:27` chỉ nhận câu hỏi và LLM — không có
   `agent_id`, `run_id`, `expires_at` hay principal. `run_once()` có nhận `principal_id`
   (`agent/loop.py:57-58`) nhưng khi rơi về baseline thì gọi `_naive_loop(message, llm)` ở
   `agent/loop.py:73`, tức là bỏ luôn danh tính người dùng; không có gì để kiểm quyền hay
   ghi lại "ai đã làm gì".

2. **Ai cho phép `http_post`? Dẫn file/hàm:**
   Không có policy nào. Không có kiểm mục đích, quyền hay loại dữ liệu trước `read_customer`
   (`agent/loop.py:38`) và `http_post` (`agent/loop.py:44`). Người thực sự "quyết định gửi" là
   chỉ thị nằm trong ticket: `llm.find_injection(combined_text)` (`agent/loop.py:34`) trích
   `customer_ids` và `target_url` từ **nội dung ticket** (dữ liệu không tin cậy), rồi vòng lặp
   ở `agent/loop.py:36-44` làm theo. Ticket là dữ liệu nhưng baseline xử lý chỉ thị bên trong
   như lệnh. `tools.http_post()` chỉ chặn URL ngoài `127.0.0.1:10024`
   (`agent/tools.py:76-83`); nó không quyết định dữ liệu nào được gửi.

3. **Nếu gửi sai PII ra sink, bằng chứng ở đâu? Dẫn file/hàm:**
   Body POST được tạo ở `agent/loop.py:44`: `{"records": collected}` — `collected` là nguyên
   hồ sơ khách (CCCD, SĐT, STK, email) đọc ở `agent/loop.py:38`; `requests.post` gửi đi ở
   `agent/tools.py:84`. Sink ghi mỗi POST thành một dòng JSON `{"path", "body"}` vào
   `reports/sink.log` (`sink/sink.py:37` định nghĩa `LOG_PATH`, `sink/sink.py:45-47` ghi file).
   Baseline không có ledger nên `reports/sink.log` (chép thành `reports/attack-before.log`)
   là bằng chứng duy nhất — ở phía người nhận, không phải phía agent.
