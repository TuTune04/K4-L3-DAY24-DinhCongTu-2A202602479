"""BƯỚC 3c — trifecta split + egress allowlist (13'). ĐÂY LÀ PHẦN KHÓ NHẤT.

Đọc CHECKPOINTS.md (§3c) trước khi viết code. Tóm tắt yêu cầu:

Tách 1 yêu cầu người dùng thành ít nhất 2 run riêng biệt — KHÔNG run nào
được cầm cả 3 chân của trifecta cùng lúc:

    Run A: gọi search_docs (untrusted content).
           KHÔNG gọi read_customer. KHÔNG gọi http_post.
    Run B: gọi read_customer (private data).
           CHỈ nhận input là TYPED, ĐÃ SANITIZE từ Run A — ví dụ
           list[int] ticket id trích từ TÊN FILE (vd "ticket-007.md" -> 7),
           KHÔNG BAO GIỜ nhận nguyên văn text của document. free text của
           attacker không được đi xa hơn Run A.

Mọi lần gọi tool (allow HAY deny) phải:
  1. Đi qua `agent.policy.check()` TRƯỚC KHI tool thật sự chạy.
  2. Được ghi vào ledger qua `agent.ledger.append()` — cả khi deny.
Nếu policy deny, KHÔNG được gọi tool đó.

--- Gợi ý kiến trúc (không bắt buộc theo đúng, nhưng đủ để làm trong 13') ---

data/customers.json có field `related_tickets: list[int]` cho mỗi khách
hàng — đây là NGUỒN TIN CẬY để map ticket_id -> customer_id, KHÔNG map qua
customer_id mà attacker nhúng trong nội dung document. Cụ thể:

    Run A: search_docs(message) -> lấy list[int] ticket_id từ TÊN FILE của
           các doc khớp (vd "ticket-999.md" -> 999). Cũng chạy
           llm.find_injection() trên text để log lại (KHÔNG dùng
           customer_id mà nó trả về).
    Run B: với mỗi ticket_id nhận từ Run A, tìm customer nào trong
           customers.json có ticket_id trong related_tickets, rồi
           read_customer(customer_id) đó — không phải customer_id lấy từ
           text tự do.

Vì sao cách này chống được một chỉ thị viết không dấu / lookalike: filter
chuỗi thô sẽ luôn có thể bị né bằng cách viết lại chỉ thị, nhưng nếu Run B
không bao giờ ĐỌC free text để quyết định gọi ai, thì việc né filter chuỗi
trở nên vô nghĩa — đây là containment (kiến trúc), khác với mitigation
(bộ lọc). Sinh viên NÊN thử filter chuỗi trước, rồi tự phá nó bằng
một bản viết lại không dấu của lure, trước khi chuyển sang cách này.

Interface bắt buộc (agent/loop.py import và gọi hàm này nếu tồn tại):

    handle(message: str, llm, log_dir: pathlib.Path | None = None,
           principal_id: str = "support_l1") -> str
        `llm` cung cấp:
            llm.find_injection(text: str) -> InjectedInstruction | None
            llm.summarize(docs: list[dict]) -> str
        `log_dir` là thư mục chứa ledger.jsonl (mặc định: reports/).
        Mỗi tool call truyền principal_id, requested_tool, agent_scopes,
        parent_scopes và expires_at vào PolicyContext; ledger ghi
        on_behalf_of = principal_id, agent_id, run_id, expires_at.
        Principal chỉ được tra trong data/principals.json. Run B không
        được đọc customer cho support_l1; dpo vẫn đọc được khách hợp lệ.
        Trả về câu trả lời cuối cùng hiển thị cho người dùng — hành vi
        quan sát được từ ngoài (CLI) không đổi so với trước khi contain,
        chỉ có sink log và ledger là khác.
"""
from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from agent import ledger, pii, tools
from agent.policy import PolicyContext, check

REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"
DEFAULT_LEDGER_PATH = REPORTS_DIR / "ledger.jsonl"

AGENT_ID = "lab24-agent"
RUN_TTL = timedelta(minutes=15)
# Quyền của agent điều phối (cha). Mỗi run con chỉ nhận đúng một chân của
# trifecta và phải nằm trong tập này (delegation_depth=1).
ORCHESTRATOR_SCOPES = ("search_docs", "read_customer", "http_post")
RUN_A_SCOPES = ("search_docs",)
RUN_B_SCOPES = ("read_customer",)
EGRESS_SCOPES = ("http_post",)

# Chỉ nhận đúng dạng "ticket-007.md"; "ticket-904b.md" hay tên lạ không đi qua ranh giới.
_TICKET_FILE_RE = re.compile(r"^ticket-(\d+)\.md$")


class RunnerScaffoldPending(NotImplementedError):
    """Only the original 3c stub uses this to enable the CP1/CP2 baseline."""


@dataclass(frozen=True)
class _Session:
    """Danh tính của một lần handle(): ai ra lệnh, agent nào, hết hạn khi nào."""
    principal_id: str
    request_id: str
    expires_at: str
    ledger_path: Path


def _args_hash(args: dict) -> str:
    canonical = json.dumps(args, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _authorize(session: _Session, run: str, tool: str, args: dict, *, classification: str,
               purpose: str, scopes: tuple[str, ...], egress: bool = False) -> bool:
    """PEP: policy.check() rồi ghi ledger (cả allow lẫn deny) TRƯỚC khi tool chạy."""
    run_id = f"{session.request_id}-{run}"
    agent_owner = f"{AGENT_ID}/{run_id}"
    context = PolicyContext(
        data_classification=classification,
        request_purpose=purpose,
        agent_owner=agent_owner,
        delegation_depth=1,
        egress_enabled=egress,
        principal_id=session.principal_id,
        requested_tool=tool,
        agent_scopes=scopes,
        parent_scopes=ORCHESTRATOR_SCOPES,
        expires_at=session.expires_at,
    )
    allowed, reason = check(context)
    ledger.append({
        "ts": datetime.now(timezone.utc).isoformat(),
        "agent_id": AGENT_ID,
        "run_id": run_id,
        "on_behalf_of": session.principal_id,
        "tool": tool,
        "args_hash": _args_hash(args),
        "classification": classification,
        "purpose": purpose,
        "delegation_depth": context.delegation_depth,
        "egress_enabled": egress,
        "expires_at": session.expires_at,
        "decision": "allow" if allowed else "deny",
        "reason": reason or f"{tool}: policy không trả lý do",
    }, session.ledger_path)
    return allowed


def _run_a(session: _Session, message: str, llm) -> tuple[list[dict], list[int], object]:
    """Run A: chỉ đọc corpus (untrusted). Không read_customer, không http_post.

    Trả về (docs đã redact PII, ticket_id lấy từ TÊN FILE, chỉ thị injection nếu có).
    """
    if not _authorize(session, "A", "search_docs", {"query": message},
                      classification="internal", purpose="summarize-tickets", scopes=RUN_A_SCOPES):
        return [], [], None
    raw_docs = tools.search_docs(message)
    # Chỉ để quan sát/ghi nhận: customer_id/URL trong chỉ thị KHÔNG được dùng để quyết định gì.
    injected = llm.find_injection("\n\n".join(d["text"] for d in raw_docs))
    docs = [{"id": d["id"], "text": pii.redact(d["text"])} for d in raw_docs]
    ticket_ids = sorted({int(m.group(1)) for d in raw_docs if (m := _TICKET_FILE_RE.match(d["id"]))})
    return docs, ticket_ids, injected


def _run_b(session: _Session, ticket_ids: list[int]) -> list[dict]:
    """Run B: chỉ nhận list[int] ticket_id. Suy customer từ related_tickets (nguồn tin cậy)."""
    # Cổng thứ nhất: principal có được mở private store không — trước khi chạm customers.json.
    if not _authorize(session, "B", "read_customer", {"ticket_ids": ticket_ids},
                      classification="restricted", purpose="support-reply", scopes=RUN_B_SCOPES):
        return []
    wanted = set(ticket_ids)
    customers = json.loads(tools.CUSTOMERS_FILE.read_text(encoding="utf-8"))
    related = [c["customer_id"] for c in customers if wanted & set(c.get("related_tickets", []))]

    records = []
    for customer_id in related:
        # Cổng thứ hai: kiểm lại ngay trước từng lần đọc hồ sơ.
        if _authorize(session, "B", "read_customer", {"customer_id": customer_id},
                      classification="restricted", purpose="support-reply", scopes=RUN_B_SCOPES):
            records.append(tools.read_customer(customer_id))
    return records


def _egress_check(session: _Session, injected) -> None:
    """Lure đòi gửi dữ liệu ra ngoài: chỉ xin phép bằng URL, không mang hồ sơ khách."""
    url = injected.target_url
    if _authorize(session, "egress", "http_post", {"url": url},
                  classification="restricted", purpose="support-reply", scopes=EGRESS_SCOPES,
                  egress=True):
        # policy luôn deny restricted + egress; nếu có ngày được allow thì cũng
        # không gửi hồ sơ, chỉ gửi xác nhận không chứa PII.
        tools.http_post(url, {"status": "egress-approved", "records": []})


def handle(message: str, llm, log_dir: Path | None = None,
           principal_id: str = "support_l1") -> str:
    now = datetime.now(timezone.utc)
    session = _Session(
        principal_id=principal_id,
        request_id=f"run-{now.strftime('%Y%m%dT%H%M%S')}-{uuid.uuid4().hex[:8]}",
        expires_at=(now + RUN_TTL).isoformat(),
        ledger_path=(Path(log_dir) / "ledger.jsonl") if log_dir else DEFAULT_LEDGER_PATH,
    )

    docs, ticket_ids, injected = _run_a(session, message, llm)
    records = _run_b(session, ticket_ids) if ticket_ids else []
    if injected is not None:
        _egress_check(session, injected)

    answer = llm.summarize(docs)
    if records:
        ids = ", ".join(r["customer_id"] for r in records)
        answer += f"\nHồ sơ khách gắn với ticket (đọc thay {principal_id}): {ids}."
    if injected is not None:
        answer += "\nCảnh báo: phát hiện chỉ thị cài trong ticket; yêu cầu gửi dữ liệu ra ngoài đã bị chặn."
    return answer
