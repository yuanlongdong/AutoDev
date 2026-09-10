"""Tests for vulnresearch.state_machine."""
from __future__ import annotations

from pathlib import Path

from vulnresearch.ir import extract_python
from vulnresearch.state_machine import StateMachineAnalyzer


def test_state_machine_detected(tmp_path: Path):
    p = tmp_path / "app.py"
    p.write_text(
        "STATUS_PENDING = 'pending'\n"
        "STATUS_APPROVED = 'approved'\n"
        "STATUS_PAID = 'paid'\n"
        "\n"
        "def process_order(order_id, action):\n"
        "    status = get_status(order_id)\n"
        "    if status == 'pending' and action == 'approve':\n"
        "        status = 'approved'\n"
        "    if status == 'approved' and action == 'pay':\n"
        "        status = 'paid'\n"
        "    return status\n",
        encoding="utf-8",
    )
    ir = extract_python(p)
    machines = StateMachineAnalyzer().detect_state_machines(ir)
    assert machines, "a state machine should be detected"
    sm = machines[0]
    state_names = {s.name for s in sm.states}
    assert "pending" in state_names
    assert "approved" in state_names
    assert "paid" in state_names
    assert sm.entry_state == "pending"
    # two guarded transitions
    guarded = [t for t in sm.transitions if t.guard]
    assert len(guarded) >= 2


def test_unguarded_transition_flagged(tmp_path: Path):
    p = tmp_path / "app.py"
    p.write_text(
        "def force_status(order_id):\n"
        "    status = 'pending'\n"
        "    status = 'shipped'   # no guard at all\n"
        "    return status\n",
        encoding="utf-8",
    )
    ir = extract_python(p)
    machines = StateMachineAnalyzer().detect_state_machines(ir)
    assert machines
    issues = StateMachineAnalyzer().find_illegal_transitions(machines[0])
    types = {i["type"] for i in issues}
    assert "unguarded_transition" in types, f"issues: {issues}"


def test_order_bypass_flagged(tmp_path: Path):
    p = tmp_path / "app.py"
    p.write_text(
        "def ship_direct(order_id):\n"
        "    status = 'pending'\n"
        "    status = 'paid'   # jumps straight to terminal state\n"
        "    return status\n",
        encoding="utf-8",
    )
    ir = extract_python(p)
    machines = StateMachineAnalyzer().detect_state_machines(ir)
    assert machines
    issues = StateMachineAnalyzer().find_illegal_transitions(machines[0])
    types = {i["type"] for i in issues}
    assert "order_bypass" in types, f"issues: {issues}"


def test_no_state_machine_in_plain_function(tmp_path: Path):
    p = tmp_path / "app.py"
    p.write_text(
        "def add(a, b):\n"
        "    return a + b\n",
        encoding="utf-8",
    )
    ir = extract_python(p)
    machines = StateMachineAnalyzer().detect_state_machines(ir)
    assert machines == []
