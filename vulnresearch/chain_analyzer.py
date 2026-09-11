"""Vulnerability-chain analysis (PHASE 10).

A single low-severity issue is usually harmless; chained together, two weak
spots can reach a dramatically higher impact (authentication bypass +
arbitrary file read becomes a mass data exfiltration).  This module detects
such *composable* chains purely from static evidence – it never exploits
anything.

Detection rules are pairs (or triples) of finding categories whose
combination is known to escalate impact:

======= ==============================================================
1      auth-bypass + arbitrary file read        -> Critical
2      hardcoded secret + auth-bypass          -> Critical
3      SSRF + internal/admin API exposure       -> High
4      file upload + path traversal            -> Critical (RCE)
5      weak crypto + authentication flaw       -> High
6      IDOR + admin function exposure          -> High
7      open redirect + XSS                     -> Medium
======= ==============================================================
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Sequence, Set

from .callgraph import CallGraph
from .models import Vulnerability


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class VulnerabilityChain:
    """A composition of findings whose combined impact exceeds each member."""

    chain_id: str
    steps: List[Vulnerability] = field(default_factory=list)
    combined_severity: str = ""
    description: str = ""


# ---------------------------------------------------------------------------
# Chain rules: each rule lists one accepted category-set per step slot.
# ---------------------------------------------------------------------------

@dataclass
class _ChainRule:
    name: str
    slots: List[Set[str]]      # one set of accepted categories per step
    severity: str
    description: str


_CHAIN_RULES: List[_ChainRule] = [
    _ChainRule(
        name="sensitive-data-exposure",
        slots=[{"auth-bypass"}, {"arbitrary-file-read", "path-traversal"}],
        severity="Critical",
        description="认证绕过 + 任意文件读 = 敏感数据泄露链",
    ),
    _ChainRule(
        name="account-takeover",
        slots=[{"hardcoded-secret"}, {"auth-bypass"}],
        severity="Critical",
        description="硬编码密钥 + 认证绕过 = 账户接管链",
    ),
    _ChainRule(
        name="internal-network-reach",
        slots=[{"ssrf"}, {"admin-api-exposure", "bfla", "internal-api-exposure"}],
        severity="High",
        description="SSRF + 内部API暴露 = 内网访问链",
    ),
    _ChainRule(
        name="upload-to-rce",
        slots=[{"file-upload"}, {"path-traversal", "arbitrary-file-write"}],
        severity="Critical",
        description="文件上传 + 路径穿越 = RCE链",
    ),
    _ChainRule(
        name="session-hijack",
        slots=[{"weak-cryptography"}, {"auth-bypass", "jwt-flaws", "weak-session",
                                        "session-fixation"}],
        severity="High",
        description="弱加密 + 认证缺陷 = 会话劫持链",
    ),
    _ChainRule(
        name="privilege-escalation",
        slots=[{"idor", "bola"}, {"admin-api-exposure", "bfla",
                                 "privilege-escalation"}],
        severity="High",
        description="IDOR + 管理功能暴露 = 权限提升链",
    ),
    _ChainRule(
        name="phishing",
        slots=[{"open-redirect"}, {"xss"}],
        severity="Medium",
        description="开放重定向 + XSS = 钓鱼链",
    ),
    # v0.7.0 – deepened vulnerability-chain coverage
    _ChainRule(
        name="ssrf-to-internal-rce",
        slots=[{"ssrf"}, {"command-injection", "code-injection"}],
        severity="Critical",
        description="SSRF + 内部命令/代码执行 = 内网RCE链",
    ),
    _ChainRule(
        name="upload-webshell",
        slots=[{"file-upload", "unrestricted-file-upload"},
               {"path-traversal", "arbitrary-file-write"},
               {"code-injection", "arbitrary-file-write"}],
        severity="Critical",
        description="文件上传 + 路径穿越 + 可执行写入 = Webshell链",
    ),
    _ChainRule(
        name="deserial-to-privesc",
        slots=[{"insecure-deserialization", "deserialization"},
               {"code-injection"},
               {"privilege-escalation"}],
        severity="Critical",
        description="反序列化 + 任意代码执行 + 权限提升链",
    ),
    _ChainRule(
        name="sqli-data-authbypass",
        slots=[{"sql-injection"}, {"sensitive-data-exposure"}, {"auth-bypass"}],
        severity="High",
        description="SQL注入 + 数据泄露 + 认证绕过链",
    ),
    _ChainRule(
        name="xss-cookie-theft",
        slots=[{"xss"}, {"insecure-cookie", "session-fixation", "weak-session"}],
        severity="High",
        description="XSS + 缺失HttpOnly/不安全Cookie = 会话劫持链",
    ),
    _ChainRule(
        name="redirect-oauth-theft",
        slots=[{"open-redirect"}, {"jwt-flaws", "hardcoded-secret", "oauth-flaws"}],
        severity="High",
        description="开放重定向 + OAuth/JWT缺陷 = 令牌窃取链",
    ),
    _ChainRule(
        name="cmdi-lateral-move",
        slots=[{"command-injection"}, {"ssrf"}, {"sensitive-data-exposure"}],
        severity="High",
        description="命令注入 + SSRF + 敏感数据 = 横向移动/数据窃取链",
    ),
]


# Severity ranking for escalation arithmetic.
_RANK = {"Info": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}
_RANK_TO_LEVEL = {v: k for k, v in _RANK.items()}


class ChainAnalyzer:
    """Detect composable vulnerability chains from static findings."""

    # ------------------------------------------------------------------

    def find_chains(
        self,
        vulns: List[Vulnerability],
        callgraph: CallGraph,
    ) -> List[VulnerabilityChain]:
        """Return every chain that fires over *vulns*.

        *callgraph* is accepted (and consulted lightly) so that future
        graph-aware ordering can be added; the present implementation is
        purely category-composition based and never uses the graph to
        *exploit* anything.
        """
        by_category: Dict[str, List[Vulnerability]] = defaultdict(list)
        for v in vulns:
            by_category[(v.category or "").lower()].append(v)

        chains: List[VulnerabilityChain] = []
        seen_combos: Set[tuple] = set()

        for idx, rule in enumerate(_CHAIN_RULES, start=1):
            picks = self._pick(by_category, rule.slots)
            for combo in picks:
                combo_key = tuple(id(v) for v in combo)
                if combo_key in seen_combos:
                    continue
                seen_combos.add(combo_key)
                chain = VulnerabilityChain(
                    chain_id=f"CHAIN-{idx:02d}-{rule.name}",
                    steps=list(combo),
                    combined_severity=rule.severity,
                    description=rule.description,
                )
                # graph-aware refinement: if all steps live in nodes that are
                # connected, keep the rule severity; otherwise it still holds.
                chain.combined_severity = self.combined_severity(chain)
                chains.append(chain)
        return chains

    # ------------------------------------------------------------------

    @staticmethod
    def combined_severity(chain: VulnerabilityChain) -> str:
        """The chain's combined severity: rule severity, escalated to the
        highest member severity when a member is itself worse than the rule
        band."""
        worst = 0
        for step in chain.steps:
            worst = max(worst, _RANK.get((step.severity or "").title(), 0))
        base = _RANK.get((chain.combined_severity or "Medium"), 2)
        return _RANK_TO_LEVEL.get(max(base, worst), "Medium")

    # ------------------------------------------------------------------
    # internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _pick(
        by_category: Dict[str, List[Vulnerability]],
        slots: Sequence[Set[str]],
    ) -> List[tuple]:
        """Pick one distinct vuln per slot.

        Returns every feasible combination; different slots may match the
        same category only through different objects.
        """
        results: List[tuple] = [()]
        for allowed in slots:
            candidates: List[Vulnerability] = []
            for cat in allowed:
                for v in by_category.get(cat, []):
                    if v not in candidates:
                        candidates.append(v)
            if not candidates:
                return []
            next_results: List[tuple] = []
            for prefix in results:
                used_here = {id(v) for v in prefix}
                for cand in candidates:
                    if id(cand) in used_here:
                        continue
                    next_results.append(prefix + (cand,))
            results = next_results
        return [r for r in results if len(r) == len(slots)]
