"""Root-cause analysis (PHASE 9).

Moves from *surface-level findings* to *systemic design defects*.  A
:class:`RootCause` answers "what class of mistake was made repeatedly across
the codebase?" rather than "which line looks suspicious?".  Concretely it maps
the structured fields of a :class:`~vulnresearch.models.Vulnerability`
(``category`` / ``sink.type`` / ``sanitizer.present`` / ``authorization.status``)
onto one of eight root-cause classes and produces a searchable ``pattern`` that
later passes (variant analysis) can use to hunt the same bug family.

Pure Python standard library only; no target code execution, no network I/O.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Tuple

from .models import Vulnerability


# ---------------------------------------------------------------------------
# Root-cause category vocabulary (fixed by the SKILL PHASE 9 contract)
# ---------------------------------------------------------------------------

MISSING_INPUT_VALIDATION = "missing_input_validation"
MISSING_AUTHORIZATION = "missing_authorization"
INSECURE_DEFAULT = "insecure_default"
UNSAFE_DESERIALIZATION = "unsafe_deserialization"
WEAK_CRYPTO = "weak_crypto"
RACE_CONDITION = "race_condition"
TRUST_BOUNDARY_VIOLATION = "trust_boundary_violation"
OTHER = "other"

ROOT_CAUSE_CATEGORIES: Tuple[str, ...] = (
    MISSING_INPUT_VALIDATION,
    MISSING_AUTHORIZATION,
    INSECURE_DEFAULT,
    UNSAFE_DESERIALIZATION,
    WEAK_CRYPTO,
    RACE_CONDITION,
    TRUST_BOUNDARY_VIOLATION,
    OTHER,
)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class RootCause:
    """A systemic defect inferred from one or more findings.

    Attributes:
        description: human-readable statement of the defect class.
        category: one of :data:`ROOT_CAUSE_CATEGORIES`.
        affected_components: files / functions implicated by the defect.
        pattern: a searchable (regex) pattern used to hunt the same bug family
            across the codebase (dangerous function names, error idioms, ...).
    """

    description: str
    category: str
    affected_components: List[str] = field(default_factory=list)
    pattern: str = ""


# ---------------------------------------------------------------------------
# Default search patterns per root-cause class
# ---------------------------------------------------------------------------

_DEFAULT_PATTERNS: Dict[str, str] = {
    MISSING_INPUT_VALIDATION: (
        r"(?:execute|executemany|raw|query|os\.system|subprocess\."
        r"(?:run|Popen|call)|open\s*\(|send_file\s*\(|requests\.(?:get|post)"
    ),
    MISSING_AUTHORIZATION: (
        r"\b(?:user_id|order_id|account_id|doc_id|file_id|id|pk)\b"
        r"(?!.*\b(?:check_owner|is_owner|assert_owner|belongs_to)\b)"
    ),
    INSECURE_DEFAULT: (
        r"(?i)(?:api[_-]?key|secret|password|passwd|token)\s*=\s*['\"]"
        r"|\bdebug\s*=\s*True|\bhost\s*=\s*['\"]0\.0\.0\.0['\"]"
    ),
    UNSAFE_DESERIALIZATION: (
        r"(?:pickle\.(?:load|loads|Unpickler)|marshal\.loads|yaml\.load\s*\()"
    ),
    WEAK_CRYPTO: r"\b(?:hashlib\.)?(?:md5|sha1)\s*\(|\.new\s*\(\s*['\"](?:md5|sha1)['\"]|\bDES\b|MODE_ECB",
    RACE_CONDITION: r"\b(?:TOCTOU|check_then_use|double_check)\b",
    TRUST_BOUNDARY_VIOLATION: (
        r"(?:requests\.(?:get|post|put|delete|request)|urllib\.request\."
        r"(?:urlopen|Request)|redirect\s*\()"
    ),
    OTHER: "",
}


class RootCauseAnalyzer:
    """Infer systemic root causes from individual findings."""

    # Per-category root-cause descriptors.  Each entry returns
    # ``(category, description, pattern)``.
    #
    # Note: ``sanitizer.present == "UNKNOWN"`` is treated as *no evidence of
    # sanitisation* – a finding whose sanitiser slot was never investigated is
    # not, by definition, sanitised.
    @staticmethod
    def _component(vuln: Vulnerability) -> List[str]:
        parts: List[str] = []
        if vuln.file:
            parts.append(vuln.function and f"{vuln.file}:{vuln.function}" or vuln.file)
        return parts

    def analyze(self, vuln: Vulnerability) -> RootCause:
        """Infer the :class:`RootCause` behind a single *vuln*."""
        cat = (vuln.category or "").lower()
        component = self._component(vuln)
        authz_missing = vuln.authorization.status in {"MISSING", "BYPASSED"} \
            or vuln.authorization.status != "PRESENT"

        # --- 1. injection families: missing input validation -------------
        # The detector has already confirmed the dangerous construction
        # (f-string / concatenation / shell=True); a runtime "sanitizer" flag
        # only affects evidence grading, not the structural root cause.
        if cat in {"sql-injection", "nosql-injection"}:
            return RootCause(
                description="共享查询构造器允许未参数化字符串拼接",
                category=MISSING_INPUT_VALIDATION,
                affected_components=component,
                pattern=r"(?:execute|executemany|raw|query|find_one|find\s*\()",
            )
        if cat == "command-injection":
            return RootCause(
                description="直接将用户输入传入 shell 执行",
                category=MISSING_INPUT_VALIDATION,
                affected_components=component,
                pattern=r"(?:os\.system|os\.popen|subprocess\.(?:run|Popen|call)"
                        r"|check_output|shell\s*=\s*True)",
            )
        if cat in {"path-traversal", "arbitrary-file-read", "arbitrary-file-write"}:
            return RootCause(
                description="未对文件路径进行规范化和目录限制",
                category=MISSING_INPUT_VALIDATION,
                affected_components=component,
                pattern=r"\bopen\s*\(|\bread_text\s*\(|\bwrite_text\s*\("
                        r"|send_file\s*\(|send_from_directory",
            )
        if cat in {"xss", "ssti"}:
            return RootCause(
                description="输出到浏览器/模板前未做上下文相关编码",
                category=MISSING_INPUT_VALIDATION,
                affected_components=component,
                pattern=r"(?:Markup\s*\(|mark_safe\s*\(|render_template_string\s*\(|format_html)",
            )
        if cat in {"file-upload", "crlf-injection"}:
            return RootCause(
                description="上传/重定向等外部输入未经过滤与白名单校验",
                category=MISSING_INPUT_VALIDATION,
                affected_components=component,
                pattern=r"request\.files|\.save\s*\(|secure_filename",
            )

        # --- 2. authorisation gaps ---------------------------------------
        if cat in {"idor", "bola", "bfla", "object-level-authz-failure",
                   "admin-api-exposure"} and authz_missing:
            return RootCause(
                description="只认证不授权，缺少对象级权限检查",
                category=MISSING_AUTHORIZATION,
                affected_components=component,
                pattern=_DEFAULT_PATTERNS[MISSING_AUTHORIZATION],
            )
        if cat in {"auth-bypass", "mfa-bypass", "jwt-flaws", "oauth-flaws",
                   "session-fixation", "weak-session"}:
            return RootCause(
                description="认证机制薄弱或可被绕过，未强制身份验证",
                category=MISSING_AUTHORIZATION,
                affected_components=component,
                pattern=r"@(?:login_required|jwt_required|auth_required)"
                        r"|verify_token|check_password",
            )

        # --- 3. insecure defaults / hardcoded secrets --------------------
        if cat in {"hardcoded-secret", "secret", "insecure-defaults",
                   "debug-interface", "unsafe-configuration"}:
            return RootCause(
                description="凭据硬编码在源码中或使用了不安全的默认配置",
                category=INSECURE_DEFAULT,
                affected_components=component,
                pattern=_DEFAULT_PATTERNS[INSECURE_DEFAULT],
            )

        # --- 4. dangerous deserialisation ---------------------------------
        if cat in {"insecure-deserialization", "deserialization", "xxe"}:
            return RootCause(
                description="使用不安全的反序列化器处理不可信数据",
                category=UNSAFE_DESERIALIZATION,
                affected_components=component,
                pattern=_DEFAULT_PATTERNS[UNSAFE_DESERIALIZATION],
            )

        # --- 5. weak cryptography ----------------------------------------
        if cat == "weak-cryptography":
            return RootCause(
                description="使用已被破解或弱密钥长度的加密原语",
                category=WEAK_CRYPTO,
                affected_components=component,
                pattern=_DEFAULT_PATTERNS[WEAK_CRYPTO],
            )

        # --- 6. race conditions ------------------------------------------
        if cat in {"race-condition", "double-spend", "replay"}:
            return RootCause(
                description="检查与使用之间存在竞争窗口，缺少原子性保护",
                category=RACE_CONDITION,
                affected_components=component,
                pattern=_DEFAULT_PATTERNS[RACE_CONDITION],
            )

        # --- 7. trust-boundary violations --------------------------------
        if cat == "ssrf":
            return RootCause(
                description="服务端发起请求时未验证目标地址",
                category=TRUST_BOUNDARY_VIOLATION,
                affected_components=component,
                pattern=_DEFAULT_PATTERNS[TRUST_BOUNDARY_VIOLATION],
            )
        if cat == "open-redirect":
            return RootCause(
                description="重定向目标未做白名单校验，跨越了跳转信任边界",
                category=TRUST_BOUNDARY_VIOLATION,
                affected_components=component,
                pattern=r"\b(?:redirect|HttpResponseRedirect)\s*\(",
            )
        if cat in {"privilege-escalation", "tenant-isolation-failure",
                   "workflow-bypass", "state-machine-bypass"}:
            return RootCause(
                description="跨权限/租户/状态机边界时缺少强制校验",
                category=TRUST_BOUNDARY_VIOLATION,
                affected_components=component,
                pattern=r"\b(?:tenant|role|privilege)\b",
            )

        # --- 8. fallback --------------------------------------------------
        return RootCause(
            description=f"未明确归类的缺陷（category={cat or 'unknown'}）",
            category=OTHER,
            affected_components=component,
            pattern=_DEFAULT_PATTERNS[OTHER],
        )

    # ------------------------------------------------------------------

    def analyze_batch(self, vulns: List[Vulnerability]) -> List[RootCause]:
        """Analyse *vulns* and merge duplicate root causes.

        Two findings map onto the same :class:`RootCause` when they share the
        ``(category, description, pattern)`` triple; their affected
        components are merged (order-preserving, de-duplicated).
        """
        merged: Dict[Tuple[str, str, str], RootCause] = {}
        for vuln in vulns:
            rc = self.analyze(vuln)
            key = (rc.category, rc.description, rc.pattern)
            existing = merged.get(key)
            if existing is None:
                merged[key] = rc
            else:
                seen = set(existing.affected_components)
                for comp in rc.affected_components:
                    if comp not in seen:
                        existing.affected_components.append(comp)
                        seen.add(comp)
        return list(merged.values())

    # ------------------------------------------------------------------

    def root_cause_to_pattern(self, rc: RootCause) -> str:
        """Return the searchable pattern for a root cause.

        Uses ``rc.pattern`` when the analyzer already recorded one, otherwise
        falls back to the canonical default pattern for the root-cause class.
        """
        if rc.pattern:
            return rc.pattern
        return _DEFAULT_PATTERNS.get(rc.category, "")
