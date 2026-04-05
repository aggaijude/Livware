"""
memory_manager.py — Persistent project memory system.

Maintains a JSON file that tracks project progress, decisions, issues,
and current focus. Enables session continuity across restarts.
"""

from __future__ import annotations

import json
import os
import time
from typing import Optional

from config import MEMORY_FILE_PATH

# ──────────────────────────── Default Structure ─────────────────────

DEFAULT_MEMORY = {
    "project_name": "AI Hybrid Antivirus",
    "version": "1.0.0",
    "last_updated": "",
    "completed_steps": [],
    "pending_steps": [
        "Config & paths setup",
        "Feature extractor built",
        "ML model integration",
        "ClamAV integration",
        "YARA engine integration",
        "Scanner orchestrator",
        "Quarantine system",
        "Memory system",
        "UI styles & themes",
        "Custom widgets",
        "Sidebar navigation",
        "Dashboard page",
        "Scan File page",
        "Scan Folder page",
        "Quarantine view page",
        "Logs view page",
        "Settings page",
        "Main window assembly",
        "Entry point & launch",
        "Integration testing",
    ],
    "current_focus": "",
    "known_issues": [],
    "decisions": [
        "Using LightGBM as ML backend",
        "Using PyQt6 for desktop UI",
        "Using subprocess for ClamAV (not daemon)",
        "16-feature PE vector for ML input",
        "Priority: ClamAV > YARA > ML",
    ],
    "architecture": {
        "engine": [
            "feature_extractor.py",
            "ml_model.py",
            "clamav.py",
            "yara_engine.py",
            "scanner.py",
            "quarantine.py",
        ],
        "ui": [
            "main_window.py",
            "sidebar.py",
            "styles.py",
            "pages/dashboard.py",
            "pages/scan_file.py",
            "pages/scan_folder.py",
            "pages/quarantine_view.py",
            "pages/logs_view.py",
            "pages/settings.py",
        ],
        "memory": ["memory_manager.py"],
    },
    "scan_stats": {
        "total_scans": 0,
        "malware_found": 0,
        "files_quarantined": 0,
        "last_scan_date": "",
    },
    "notes": [],
}


# ──────────────────────────── Manager ───────────────────────────────

def load_memory() -> dict:
    """
    Load project memory from disk.
    Creates a new memory file with defaults if missing.
    """
    if os.path.isfile(MEMORY_FILE_PATH):
        try:
            with open(MEMORY_FILE_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
            # Merge with defaults to pick up any new fields
            merged = {**DEFAULT_MEMORY, **data}
            return merged
        except Exception as e:
            print(f"[memory] Failed to load memory: {e}")

    # Create new
    save_memory(DEFAULT_MEMORY)
    return dict(DEFAULT_MEMORY)


def save_memory(data: dict) -> None:
    """Persist memory to disk with updated timestamp."""
    data["last_updated"] = time.strftime("%Y-%m-%d %H:%M:%S")
    try:
        with open(MEMORY_FILE_PATH, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    except Exception as e:
        print(f"[memory] Failed to save memory: {e}")


def update_step(step: str, status: str = "completed") -> None:
    """
    Move a step between pending and completed.

    status: 'completed' | 'pending'
    """
    mem = load_memory()

    if status == "completed":
        if step in mem["pending_steps"]:
            mem["pending_steps"].remove(step)
        if step not in mem["completed_steps"]:
            mem["completed_steps"].append(step)
    elif status == "pending":
        if step in mem["completed_steps"]:
            mem["completed_steps"].remove(step)
        if step not in mem["pending_steps"]:
            mem["pending_steps"].append(step)

    save_memory(mem)


def mark_completed(step: str) -> None:
    """Shortcut to mark a step as completed."""
    update_step(step, "completed")


def set_focus(focus: str) -> None:
    """Set the current focus area."""
    mem = load_memory()
    mem["current_focus"] = focus
    save_memory(mem)


def add_issue(issue: str) -> None:
    """Record a known issue."""
    mem = load_memory()
    if issue not in mem["known_issues"]:
        mem["known_issues"].append(issue)
        save_memory(mem)


def resolve_issue(issue: str) -> None:
    """Remove a resolved issue."""
    mem = load_memory()
    if issue in mem["known_issues"]:
        mem["known_issues"].remove(issue)
        save_memory(mem)


def add_decision(decision: str) -> None:
    """Record an architectural decision."""
    mem = load_memory()
    if decision not in mem["decisions"]:
        mem["decisions"].append(decision)
        save_memory(mem)


def add_note(note: str) -> None:
    """Add a free-form note."""
    mem = load_memory()
    timestamped = f"[{time.strftime('%Y-%m-%d %H:%M')}] {note}"
    mem["notes"].append(timestamped)
    save_memory(mem)


def update_scan_stats(
    total_delta: int = 0,
    malware_delta: int = 0,
    quarantine_delta: int = 0,
) -> None:
    """Increment scan statistics."""
    mem = load_memory()
    stats = mem.get("scan_stats", DEFAULT_MEMORY["scan_stats"].copy())
    stats["total_scans"] += total_delta
    stats["malware_found"] += malware_delta
    stats["files_quarantined"] += quarantine_delta
    stats["last_scan_date"] = time.strftime("%Y-%m-%d %H:%M:%S")
    mem["scan_stats"] = stats
    save_memory(mem)


def get_summary() -> str:
    """Return a human-readable project status summary."""
    mem = load_memory()
    completed = len(mem.get("completed_steps", []))
    pending = len(mem.get("pending_steps", []))
    total = completed + pending
    pct = (completed / total * 100) if total > 0 else 0

    lines = [
        f"╔══════════════════════════════════════════╗",
        f"║   {mem.get('project_name', 'Project')} — Status   ",
        f"╠══════════════════════════════════════════╣",
        f"║  Progress: {completed}/{total} ({pct:.0f}%)",
        f"║  Last Updated: {mem.get('last_updated', 'N/A')}",
        f"║  Current Focus: {mem.get('current_focus', 'N/A')}",
        f"╠══════════════════════════════════════════╣",
        f"║  Completed: {', '.join(mem.get('completed_steps', [])[-5:]) or 'None'}",
        f"║  Pending: {', '.join(mem.get('pending_steps', [])[:5]) or 'None'}",
        f"║  Issues: {len(mem.get('known_issues', []))}",
        f"╚══════════════════════════════════════════╝",
    ]
    return "\n".join(lines)


def get_progress_data() -> dict:
    """Return structured progress data for the UI."""
    mem = load_memory()
    completed = len(mem.get("completed_steps", []))
    pending = len(mem.get("pending_steps", []))
    total = completed + pending
    return {
        "completed": completed,
        "pending": pending,
        "total": total,
        "percent": (completed / total * 100) if total > 0 else 0,
        "current_focus": mem.get("current_focus", ""),
        "scan_stats": mem.get("scan_stats", {}),
    }
