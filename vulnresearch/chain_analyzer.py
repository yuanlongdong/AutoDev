"""Vulnerability-chain analysis (PHASE 10).

A chain is only reported when its component findings have sufficient evidence
and there is a static program relationship between the affected locations.
This module never executes target code or performs network I/O.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Sequence, Set

from .callgraph import CallGraph
from .models import Vulnerability


@dataclass
class VulnerabilityChain:
    """A composition of findings whose combined impact exceeds each member."""

    chain_id: str
    steps: List[Vulnerability] = field(default_factory=list)
    combined_severity: str = ""
    description: str = ""


@dataclass
class _ChainRule:
    name: str
    slots: List[Set[str]]
    severity: str
    description: str


_CHAIN_RULES: List[_ChainRule] = [
    _ChainRule("sensitive-data-exposure", [{"auth-bypass"}, {"arbitrary-file-read", "path-traversal"}], "Critical", "认证绕过 + 任意文件读 = 敏感数据泄露链"),
    _ChainRule("account-takeover", [{"hardcoded-secret"}, {"auth-bypass"}], "Critical", "硬编码密钥 + 认证绕过 = 账户接管链"),
    _ChainRule("internal-network-reach", [{"ssrf"}, {"admin-api-exposure", "bfla", "internal-api-exposure"}], "High", "SSRF + 内部API暴露 = 内网访问链"),
    _ChainRule("upload-to-rce", [{"file-upload"}, {"path-traversal", "arbitrary-file-write"}], "Critical", "文件上传 + 路径穿越 = RCE链"),
    _ChainRule("session-hijack", [{"weak-cryptography"}, {"auth-bypass", "jwt-flaws", "weak-session", "session-fixation"}], "High", "弱加密 + 认证缺陷 = 会话劫持链"),
    _ChainRule("privilege-escalation", [{"idor", "bola"}, {"admin-api-exposure", "bfla", "privilege-escalation"}], "High", "IDOR + 管理功能暴露 = 权限提升链"),
    _ChainRule("phishing", [{"open-redirect"}, {"xss"}], "Medium", "开放重定向 + XSS = 钓鱼链"),
    _ChainRule("ssrf-to-internal-rce", [{"ssrf"}, {"command-injection", "code-injection"}], "Critical", "SSRF + 内部命令/代码执行 = 内网RCE链"),
    _ChainRule("upload-webshell", [{"file-upload", "unrestricted-file-upload"}, {"path-traversal", "arbitrary-file-write"}, {"code-injection", "arbitrary-file-write"}], "Critical", "文件上传 + 路径穿越 + 可执行写入 = Webshell链"),
    _ChainRule("deserial-to-privesc", [{"insecure-deserialization", "deserialization"}, {"code-injection"}, {"privilege-escalation"}], "Critical", "反序列化 + 任意代码执行 + 权限提升链"),
    _ChainRule("sqli-data-authbypass", [{"sql-injection"}, {"sensitive-data-exposure"}, {"auth-bypass"}], "High", "SQL注入 + 数据泄露 + 认证绕过链"),
    _ChainRule("xss-cookie-theft", [{"xss"}, {"insecure-cookie", "session-fixation", "weak-session"}], "High", "XSS + 缺失HttpOnly/不安全Cookie = 会话劫持链"),
    _ChainRule("redirect-oauth-theft", [{"open-redirect"}, {"jwt-flaws", "hardcoded-secret", "oauth-flaws"}], "High", "开放重定向 + OAuth/JWT缺陷 = 令牌窃取链"),
    _ChainRule("cmdi-lateral-move", [{"command-injection"}, {"ssrf"}, {"sensitive-data-exposure"}], "High", "命令注入 + SSRF + 敏感数据 = 横向移动/数据窃取链"),
]

_RANK = {"Info": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}
_RANK_TO_LEVEL = {v: k for k, v in _RANK.items()}
_EVIDENCE_RANK = {"E0": 0, "E1": 1, "E2": 2, "E3": 3, "E4": 4, "E5": 5}


class ChainAnalyzer:
    """Detect composable vulnerability chains from static findings."""

    def find_chains(self, vulns: List[Vulnerability], callgraph: CallGraph) -> List[VulnerabilityChain]:
        by_category: Dict[str, List[Vulnerability]] = defaultdict(list)
        for v in vulns:
            if _EVIDENCE_RANK.get((v.evidence.level or "E0").upper(), 0) < 2:
                continue
            if (v.status or "").lower() in {"potential", "false-positive", "rejected"}:
                continue
            by_category[(v.category or "").lower()].append(v)

        chains: List[VulnerabilityChain] = []
        seen_combos: Set[tuple] = set()
        for idx, rule in enumerate(_CHAIN_RULES, start=1):
            for combo in self._pick(by_category, rule.slots):
                combo_key = tuple(id(v) for v in combo)
                if combo_key in seen_combos or not self._has_program_relationship(combo, callgraph):
                    continue
                seen_combos.add(combo_key)
                chain = VulnerabilityChain(
                    chain_id=f"CHAIN-{idx:02d}-{rule.name}",
                    steps=list(combo),
                    combined_severity=rule.severity,
                    description=rule.description,
                )
                chain.combined_severity = self.combined_severity(chain)
                chains.append(chain)
        return chains

    @staticmethod
    def combined_severity(chain: VulnerabilityChain) -> str:
        worst = 0
        for step in chain.steps:
            worst = max(worst, _RANK.get((step.severity or "").title(), 0))
        base = _RANK.get((chain.combined_severity or "Medium").title(), 2)
        return _RANK_TO_LEVEL.get(max(base, worst), "Medium")

    @staticmethod
    def _pick(by_category: Dict[str, List[Vulnerability]], slots: Sequence[Set[str]]) -> List[tuple]:
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
                    if id(cand) not in used_here:
                        next_results.append(prefix + (cand,))
            results = next_results
        return [r for r in results if len(r) == len(slots)]

    @staticmethod
    def _has_program_relationship(combo: Sequence[Vulnerability], callgraph: CallGraph) -> bool:
        """Require a plausible static relationship between every adjacent step.

        A same-file match is only accepted when both findings point to the same
        function, or when an older detector omitted function metadata on one
        side. Two different known functions in the same file are not enough:
        they must be connected by the call graph.
        """
        for left, right in zip(combo, combo[1:]):
            if left.file and right.file and left.file == right.file:
                lf = (left.function or "").strip()
                rf = (right.function or "").strip()
                if not lf or not rf or lf == rf:
                    continue
            lf = (left.function or "").strip()
            rf = (right.function or "").strip()
            if not lf or not rf:
                return False
            if not ChainAnalyzer._connected(callgraph, lf, rf):
                return False
        return True

    @staticmethod
    def _unique_nodes(callgraph: CallGraph, name: str) -> Set[str]:
        """Resolve a function name only when it maps unambiguously."""
        if not name:
            return set()
        exact = {name} if name in callgraph.nodes else set()
        if exact:
            return exact
        matches = {
            q for q in callgraph.nodes
            if q.endswith("." + name) or q.split(".")[-1] == name
        }
        return matches if len(matches) == 1 else set()

    @staticmethod
    def _connected(callgraph: CallGraph, left: str, right: str) -> bool:
        left_nodes = ChainAnalyzer._unique_nodes(callgraph, left)
        right_nodes = ChainAnalyzer._unique_nodes(callgraph, right)
        if not left_nodes or not right_nodes:
            return False

        def reachable(starts: Set[str], targets: Set[str]) -> bool:
            seen: Set[str] = set(starts)
            stack = list(starts)
            while stack:
                node = stack.pop()
                if node in targets:
                    return True
                for nxt in callgraph.edges.get(node, []):
                    if nxt not in seen:
                        seen.add(nxt)
                        stack.append(nxt)
            return False

        return reachable(left_nodes, right_nodes) or reachable(right_nodes, left_nodes)
