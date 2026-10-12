"""BƯỚC 3b — PEP (Policy Enforcement Point) tại tool call (15').

Cổng chặn TRƯỚC KHI tool thật sự execute. Đọc CHECKPOINTS.md (§3b).

Interface bắt buộc (tests/test_policy.py và agent/runner.py gọi trực tiếp):

    check(context: PolicyContext) -> tuple[bool, str]
        Trả về (allow, reason).
        `reason` KHÔNG BAO GIỜ được để trống — cả khi allow=True và
        allow=False. Đây là evidence audit ở Bước 4 (rubric: "Audit
        completeness = 100%" — điều kiện trượt nếu có dòng thiếu reason).

PolicyContext — 5 input gốc và các input OBO cho lớp L3:

    data_classification: str   "public" | "internal" | "restricted"
    request_purpose: str       tự do, ví dụ "reconciliation", "support-reply"
    agent_owner: str            định danh agent/run gọi tool này
    delegation_depth: int       0 = gọi trực tiếp bởi user, >0 = agent gọi agent
    egress_enabled: bool        run hiện tại có được phép gọi network không
    principal_id: str           ID người ra lệnh từ data/principals.json
    requested_tool: str         tool sắp gọi
    agent_scopes: tuple[str]    quyền tối đa của agent
    parent_scopes: tuple[str]   quyền của agent cha khi delegation_depth > 0
    expires_at: str             ISO-8601 UTC; hết hạn phải deny

Rule TỐI THIỂU bắt buộc (không được viết yếu hơn rule này):

    classification == "restricted" and egress_enabled is True  ->  DENY

Checkpoint OBO: quyền hiệu lực = principal.allowed_tools ∩ agent_scopes,
và nếu depth > 0 thì còn giao với parent_scopes. Unknown principal, scope
thiếu, run hết hạn đều deny kèm reason. Principal là fixture mô phỏng,
không phải xác thực người dùng production.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

PRINCIPALS_FILE = Path(__file__).resolve().parent.parent / "data" / "principals.json"
CLASSIFICATIONS = ("public", "internal", "restricted")


@dataclass(frozen=True)
class PolicyContext:
    data_classification: str
    request_purpose: str
    agent_owner: str
    delegation_depth: int
    egress_enabled: bool
    principal_id: str = ""
    requested_tool: str = ""
    agent_scopes: tuple[str, ...] = ()
    parent_scopes: tuple[str, ...] = ()
    expires_at: str = ""


def load_principals(path: Path | None = None) -> dict:
    """Nguồn tin cậy mô phỏng cho OBO — không phải xác thực người dùng thật."""
    return json.loads((path or PRINCIPALS_FILE).read_text(encoding="utf-8"))


def _parse_utc(value: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError):
        return None
    # Thời điểm không có múi giờ là mơ hồ -> coi như không hợp lệ (fail closed).
    return parsed if parsed.tzinfo is not None else None


def check(context: PolicyContext) -> tuple[bool, str]:
    c = context
    tool = c.requested_tool

    # 1. Phân loại dữ liệu phải thuộc tập đã biết.
    if c.data_classification not in CLASSIFICATIONS:
        return False, f"deny: data_classification {c.data_classification!r} không thuộc {CLASSIFICATIONS}"

    # 2. Rule tối thiểu: dữ liệu restricted không bao giờ đi kèm egress, kể cả với DPO.
    if c.data_classification == "restricted" and c.egress_enabled:
        return False, (f"deny: dữ liệu restricted không được đi cùng egress "
                       f"(tool={tool or '?'}, principal={c.principal_id or '?'})")

    # 3. Ai đang gọi và gọi thay ai.
    if not c.agent_owner:
        return False, "deny: thiếu agent_owner, không biết agent/run nào đang gọi tool"
    if c.delegation_depth < 0:
        return False, f"deny: delegation_depth={c.delegation_depth} không hợp lệ"
    principal = load_principals().get(c.principal_id) if c.principal_id else None
    if principal is None:
        return False, f"deny: principal {c.principal_id!r} không có trong data/principals.json"
    if not tool:
        return False, "deny: thiếu requested_tool"

    # 4. Quyền hiệu lực = allowed_tools ∩ agent_scopes (∩ parent_scopes nếu được ủy quyền).
    if tool not in principal.get("allowed_tools", []):
        return False, f"deny: principal {c.principal_id} không có quyền {tool}"
    if tool not in c.agent_scopes:
        return False, f"deny: {tool} nằm ngoài agent_scopes {list(c.agent_scopes)} của {c.agent_owner}"
    if c.delegation_depth > 0 and tool not in c.parent_scopes:
        return False, (f"deny: agent con (depth={c.delegation_depth}) không được vượt "
                       f"parent_scopes {list(c.parent_scopes)} để gọi {tool}")

    # 5. Mục đích phải nằm trong danh sách được phép của principal.
    if c.request_purpose not in principal.get("purposes", []):
        return False, f"deny: mục đích {c.request_purpose!r} không được phép cho {c.principal_id}"

    # 6. TTL của lần ủy quyền.
    expires = _parse_utc(c.expires_at)
    if expires is None:
        return False, f"deny: expires_at {c.expires_at!r} thiếu hoặc không phải ISO-8601 có múi giờ"
    if expires <= datetime.now(timezone.utc):
        return False, f"deny: ủy quyền đã hết hạn lúc {c.expires_at}"

    return True, (f"allow: {c.principal_id} được dùng {tool} cho mục đích {c.request_purpose} "
                  f"({c.data_classification}, egress={c.egress_enabled}, depth={c.delegation_depth}, "
                  f"hết hạn {c.expires_at})")
