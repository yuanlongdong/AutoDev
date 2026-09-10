"""Business-logic state-machine analysis (PHASE 7 – lightweight).

Detects simple state machines defined through ``status`` / ``state`` /
``phase`` / ``step`` variables and their transitions, then flags illegal
patterns:

* transitions with no guard (direct unconditional assignment),
* repeated / non-idempotent transitions,
* order bypass (jumping from an initial state straight to a terminal state).

This is a lightweight regex + AST-pattern implementation – it does not
perform full symbolic state-machine inference.

Pure Python standard library; no execution, no network.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

from .ir import FunctionIR, ProjectIR


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class State:
    """A single named state within a state machine."""

    name: str
    line: int


@dataclass
class Transition:
    """A directed edge between two states."""

    from_state: str
    to_state: str
    action: str
    line: int
    guard: str = ""


@dataclass
class StateMachine:
    """A detected state machine."""

    name: str
    states: List[State] = field(default_factory=list)
    transitions: List[Transition] = field(default_factory=list)
    entry_state: str = ""


# ---------------------------------------------------------------------------
# Regexes
# ---------------------------------------------------------------------------

# matches a variable name that looks like a state holder
_STATE_VAR_RE = re.compile(
    r"\b(\w*(?:status|state|phase|step)\w*)\b", re.IGNORECASE
)
# matches a constant definition:  STATUS_PENDING = "pending"
_CONST_RE = re.compile(
    r"^([A-Z][A-Z0-9_]*(?:STATUS|STATE|PHASE|STEP)[A-Z0-9_]*)\s*=\s*['\"](\w+)['\"]"
)
# matches a conditional state check:  if status == "pending" and action == "approve":
_GUARD_RE = re.compile(
    r"if\s+(\w*(?:status|state|phase|step)\w*)\s*==\s*['\"](\w+)['\"]"
    r"(?:\s+and\s+(.*?))?\s*:",
    re.IGNORECASE,
)
# matches a state assignment:  status = "approved"
_ASSIGN_RE = re.compile(
    r"^\s*(\w*(?:status|state|phase|step)\w*)\s*=\s*['\"](\w+)['\"]",
    re.IGNORECASE,
)
# entry / terminal heuristics
_ENTRY_HINTS = ("pending", "draft", "new", "init", "created", "open")
_TERMINAL_HINTS = ("paid", "shipped", "completed", "done", "cancelled", "closed", "rejected", "approved")


# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------


class StateMachineAnalyzer:
    """Detects state machines and flags illegal transitions."""

    def __init__(self) -> None:
        self._file_cache: Dict[str, List[str]] = {}

    # -- public API --------------------------------------------------------

    def detect_state_machines(self, project_ir: ProjectIR) -> List[StateMachine]:
        """Scan every function body for state-machine patterns."""
        machines: List[StateMachine] = []
        for fn in project_ir.functions:
            lines = self._read_lines(fn.path)
            sm = self._analyze_function(fn, lines)
            if sm is not None:
                machines.append(sm)
        return machines

    def find_illegal_transitions(self, sm: StateMachine) -> List[dict]:
        """Return a list of illegal-transition issues for *sm*."""
        issues: List[dict] = []
        state_names = {s.name for s in sm.states}

        for t in sm.transitions:
            # 1. no guard – the assignment was unconditional
            if not t.guard:
                issues.append({
                    "type": "unguarded_transition",
                    "transition": f"{t.from_state} -> {t.to_state}",
                    "line": t.line,
                    "description": f"Transition '{t.from_state}' -> '{t.to_state}' has no guard condition",
                })

            # 2. repeat / non-idempotent – from and to are the same state
            if t.from_state and t.from_state == t.to_state:
                issues.append({
                    "type": "non_idempotent",
                    "transition": f"{t.from_state} -> {t.to_state}",
                    "line": t.line,
                    "description": f"Self-transition '{t.from_state}' may indicate repeated execution",
                })

            # 3. order bypass – entry state jumping straight to a terminal state
            if (sm.entry_state
                    and t.from_state == sm.entry_state
                    and any(hint in t.to_state.lower() for hint in _TERMINAL_HINTS)):
                issues.append({
                    "type": "order_bypass",
                    "transition": f"{t.from_state} -> {t.to_state}",
                    "line": t.line,
                    "description": f"Jumps from entry state '{t.from_state}' directly to terminal "
                                   f"state '{t.to_state}', skipping intermediate states",
                })
        return issues

    # -- internal analysis -------------------------------------------------

    def _analyze_function(self, fn: FunctionIR, lines: List[str]) -> Optional[StateMachine]:
        start = max(0, fn.line - 1)
        end = min(len(lines), fn.end_line)
        body = lines[start:end]
        if not body:
            return None

        states: Dict[str, State] = {}
        transitions: List[Transition] = []
        pending_from: Dict[str, tuple] = {}  # var -> (from_state, guard, line)
        current_state: Dict[str, str] = {}  # var -> last assigned state

        for offset, raw in enumerate(body):
            lineno = start + offset + 1
            line = raw.strip()

            # constant state definitions
            m_const = _CONST_RE.match(line)
            if m_const:
                states.setdefault(m_const.group(2), State(m_const.group(2), lineno))
                continue

            # guarded state check:  if status == "pending" ...:
            m_guard = _GUARD_RE.match(line)
            if m_guard:
                var = m_guard.group(1).lower()
                from_state = m_guard.group(2)
                extra = m_guard.group(3) or ""
                guard = f"{var} == '{from_state}'"
                if extra:
                    guard += f" and {extra.strip()}"
                pending_from[var] = (from_state, guard, lineno)
                states.setdefault(from_state, State(from_state, lineno))
                continue

            # state assignment:  status = "approved"
            m_assign = _ASSIGN_RE.match(line)
            if m_assign:
                var = m_assign.group(1).lower()
                to_state = m_assign.group(2)
                states.setdefault(to_state, State(to_state, lineno))

                if var in pending_from:
                    from_state, guard, _ = pending_from[var]
                    transitions.append(Transition(
                        from_state=from_state, to_state=to_state,
                        action=guard, line=lineno, guard=guard,
                    ))
                    del pending_from[var]
                elif var in current_state:
                    # unguarded sequential transition from the previous state
                    from_state = current_state[var]
                    transitions.append(Transition(
                        from_state=from_state, to_state=to_state,
                        action=line, line=lineno, guard="",
                    ))
                else:
                    # initial / unconditional assignment – from unknown
                    transitions.append(Transition(
                        from_state="*", to_state=to_state,
                        action=line, line=lineno, guard="",
                    ))
                current_state[var] = to_state
                continue

        if not states and not transitions:
            return None

        # determine entry state
        entry = ""
        for s in states:
            if any(hint in s.lower() for hint in _ENTRY_HINTS):
                entry = s
                break
        if not entry and states:
            entry = next(iter(states))

        return StateMachine(
            name=fn.name,
            states=list(states.values()),
            transitions=transitions,
            entry_state=entry,
        )

    # -- source helpers ----------------------------------------------------

    def _read_lines(self, path: str) -> List[str]:
        if path not in self._file_cache:
            try:
                with open(path, encoding="utf-8", errors="replace") as fh:
                    self._file_cache[path] = fh.read().splitlines()
            except OSError:
                self._file_cache[path] = []
        return self._file_cache[path]
