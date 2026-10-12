# Secret giả trong lịch sử Git — checkpoint 4

- **Scanner và phiên bản:** Gitleaks `8.30.1` (`gitleaks version`), binary cài từ release chính thức
  `gitleaks_8.30.1_linux_x64.tar.gz`, config `.gitleaks.toml` (default rules + rule `lab24-synthetic-token`).
- **Commit chứa token giả:** `1bdd849` (`1bdd849922156c868a5ee9293d68f5b72e242d2c`,
  "chore: seed student lab with synthetic secret exercise"). File đó đã bị xoá ở commit sau,
  nên HEAD không còn token nhưng lịch sử vẫn còn.
- **File, rule và kết quả quét lịch sử:**
  `gitleaks git --config .gitleaks.toml --redact --verbose .` → `4 commits scanned`, `leaks found: 1`, exit code `1`.
  Finding duy nhất: `RuleID: lab24-synthetic-token`, `File: lab-fake-secret.txt`, `Line: 1`,
  `Commit: 1bdd849922156c868a5ee9293d68f5b72e242d2c`, giá trị được `--redact` che.
  Đây là token **giả, vô hiệu** có định dạng `LAB24-DEMO` do đề bài cài sẵn — kết quả dự kiến của
  checkpoint, không phải sự cố bảo mật thật.
- **Kết quả quét file hiện tại:** `gitleaks dir --config .gitleaks.toml --redact .` → `no leaks found`, exit `0`.
  Hook pre-commit `gitleaks-system` (repo `https://github.com/gitleaks/gitleaks`, pin `rev: v8.30.1`,
  `pass_filenames: false`) chạy `pre-commit run --all-files` → `Passed`.
- **Nếu đây là credential thật, cần xử lý thế nào:**
  1. Coi như đã lộ từ thời điểm push commit `1bdd849`: **thu hồi / rotate** credential ngay tại hệ thống
     cấp phát (vô hiệu khoá cũ, cấp khoá mới, cập nhật nơi dùng qua secret manager — không ghi vào repo).
  2. Rà log truy cập của dịch vụ đó trong khoảng thời gian lộ để tìm lần dùng bất thường.
  3. Sau khi đã rotate mới cân nhắc viết lại lịch sử (`git filter-repo`) và force-push, báo mọi người
     clone lại; fork/clone/cache cũ vẫn có thể giữ bản sao nên bước này không thay cho rotate.
  4. Ghi sự cố, thêm rule/allowlist phù hợp và bật hook để chặn lần sau.
- **Vì sao xoá file khỏi HEAD hoặc pin dependency vẫn chưa đủ:**
  Xoá file ở commit sau không xoá blob khỏi lịch sử — ai có clone/fork đều `git show 1bdd849` được, và
  credential vẫn còn hiệu lực cho tới khi bị thu hồi. Hook pre-commit chỉ chặn secret **mới** trước khi
  commit; `requirements.lock` với `--hash=sha256` chỉ bảo đảm gói cài đúng bản đã khoá (chống gói bị thay
  ở PyPI/mirror). Cả hai là biện pháp phòng ngừa cho chuỗi cung ứng, không làm một secret đã lộ trở nên vô hại;
  chỉ rotate/thu hồi mới làm được điều đó.
- **Lock dependency:** `python -m piptools compile --generate-hashes -o requirements.lock requirements.txt`
  sinh 10 package, mỗi package có `--hash=sha256:`; `python -m pip install --require-hashes -r requirements.lock`
  chạy thành công.
