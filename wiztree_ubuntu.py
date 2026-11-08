#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WizTree Ubuntu Edition — High-Speed Visual Disk Space Analyzer (Treemap)
========================================================================
Features:
- Ultra-fast os.scandir() engine with automatic Linux virtual mount filtering
  (/proc, /sys, /dev, /run, /snap, squashfs, tmpfs, etc.).
- Interactive High-DPI Cushioned Squarified Treemap (WizTree style) with:
  * Instant mode switching: [By Folders (Hierarchy)] vs [By File Types (Extensions)]
  * Smooth drill-down (double-click to zoom into any folder or file-type group)
  * Full English UI with native UTF-8 & BiDi isolation for Hebrew filenames
- Windows-Style Marquee / Rubber-Band Multi-Selection:
  * Click & drag across the Treemap to draw the classic translucent blue selection box
  * Select multiple files/folders at once
  * Batch inspection, size aggregation, batch shredding, and multi-file actions
- Live Search & Filter Bar directly above the Treemap:
  * Instant real-time filtering by name, extension (*.iso, *.mp4), category, or Hebrew keyword
  * Two visual modes: "Highlight Matches" (glowing match borders, dimmed background) vs "Show Only Matching"
  * Match counter and size accumulator
- In-Window File Inspector & Live Preview Panel:
  * Single or multi-selection metadata, size, permissions, and owner in the same window
  * Built-in Live Image Preview & UTF-8/Hebrew Text Preview
  * Interactive Top-Files list for the current view or selected folder/category
- "Search as Admin" button using Polkit (pkexec) background worker (works cleanly
  on both Wayland and X11 without display permission errors).
- Direct integration with ~/.local/bin/file_shredder_gui.py (pre-populating the
  exact target folder/file path so you never have to search for it) + built-in
  secure multi-pass file/folder shredder (supports batch shredding).
- Custom High-Res Desktop Icon & Shortcut Creator:
  * Automatically generates and installs a custom 3D glowing Treemap disk icon
  * Adds a trusted clickable icon on your Ubuntu Desktop ("עמוד הבית / שולחן העבודה") and Applications menu.

Quick Start / Installation:
    python3 wiztree_ubuntu.py --install
    python3 wiztree_ubuntu.py
"""

import base64
import datetime
import fnmatch
import json
import math
import os
import shutil
import stat
import subprocess
import sys
import zlib
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Set


# ==============================================================================
# Unicode BiDi Isolation Helper (Ensures Hebrew filenames render cleanly in English UI)
# ==============================================================================

FSI = "\u2068"  # First Strong Isolate
PDI = "\u2069"  # Pop Directional Isolate


def bidi_isolate(text: str) -> str:
    """Wraps a filename or path in Unicode Directional Isolates so Hebrew names
    never scramble surrounding English labels, parentheses, or size strings."""
    if not text:
        return ""
    return f"{FSI}{text}{PDI}"


def format_size(num_bytes: int) -> str:
    """Formats byte count into human-readable units (B, KB, MB, GB, TB)."""
    if num_bytes < 0:
        num_bytes = 0
    for unit in ("B", "KB", "MB", "GB", "TB", "PB"):
        if num_bytes < 1024.0 or unit == "PB":
            if unit == "B":
                return f"{int(num_bytes)} B"
            return f"{num_bytes:.2f} {unit}"
        num_bytes /= 1024.0
    return f"{num_bytes:.2f} PB"


# ==============================================================================
# File Category & Color Palette Definitions (WizTree High-Contrast Dark Palette)
# ==============================================================================

FILE_CATEGORIES: Dict[str, Tuple[str, str, set]] = {
    "Video": (
        "Video & Movies",
        "#e63946",  # Vibrant Crimson/Coral
        {".mp4", ".mkv", ".avi", ".mov", ".wmv", ".flv", ".webm", ".m4v", ".mpeg", ".mpg", ".ts", ".3gp"},
    ),
    "Archives & Disk Images": (
        "Archives & ISOs",
        "#f4a261",  # Warm Amber/Gold
        {".zip", ".tar", ".gz", ".bz2", ".xz", ".zst", ".7z", ".rar", ".iso", ".img", ".qcow2", ".vdi", ".vmdk", ".deb", ".rpm", ".snap", ".flatpak", ".appimage"},
    ),
    "Images & Graphics": (
        "Images & Photos",
        "#9b5de5",  # Vivid Purple
        {".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".svg", ".tiff", ".tif", ".ico", ".heic", ".raw", ".psd", ".xcf", ".ai"},
    ),
    "Audio & Music": (
        "Audio & Music",
        "#00bbf9",  # Bright Cyan
        {".mp3", ".wav", ".flac", ".ogg", ".aac", ".m4a", ".wma", ".opus", ".mid"},
    ),
    "Documents & Office": (
        "Documents & Books",
        "#3a86ff",  # Royal Blue
        {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".odt", ".ods", ".odp", ".txt", ".rtf", ".md", ".csv", ".epub", ".mobi"},
    ),
    "Code & Databases": (
        "Code, Scripts & DB",
        "#06d6a0",  # Emerald Green
        {".py", ".js", ".ts", ".html", ".css", ".c", ".cpp", ".h", ".hpp", ".rs", ".go", ".java", ".sh", ".json", ".xml", ".yaml", ".yml", ".sql", ".db", ".sqlite", ".sqlite3"},
    ),
    "System & Binaries": (
        "System, Libs & Cache",
        "#5e60ce",  # Deep Indigo
        {".so", ".a", ".o", ".ko", ".bin", ".run", ".exe", ".dll", ".log", ".bak", ".tmp", ".cache", ".swp"},
    ),
}

DEFAULT_CATEGORY_COLOR = "#6c757d"  # Slate Gray for uncategorized extensions

EXT_TO_CATEGORY: Dict[str, Tuple[str, str]] = {}
for cat_key, (_label, hex_color, ext_set) in FILE_CATEGORIES.items():
    for ext in ext_set:
        EXT_TO_CATEGORY[ext] = (cat_key, hex_color)


def classify_extension(filename: str) -> Tuple[str, str, str]:
    """Returns (normalized_ext, category_name, hex_color) for a filename."""
    lower = filename.lower()
    _, ext = os.path.splitext(lower)
    if not ext or ext == ".":
        return ("[No Ext]", "Other Files", DEFAULT_CATEGORY_COLOR)
    cat_info = EXT_TO_CATEGORY.get(ext)
    if cat_info:
        return (ext, cat_info[0], cat_info[1])
    palette = ["#4ea8de", "#52b788", "#e07a5f", "#b5838d", "#6d6875", "#43aa8b", "#f9844a"]
    color = palette[hash(ext) % len(palette)]
    return (ext, "Other Files", color)


# ==============================================================================
# Virtual Filesystem Detection for Linux
# ==============================================================================

VIRTUAL_FS_TYPES = {
    "proc", "sysfs", "devtmpfs", "devpts", "tmpfs", "squashfs",
    "cgroup", "cgroup2", "pstore", "securityfs", "debugfs", "tracefs",
    "fusectl", "configfs", "mqueue", "hugetlbfs", "autofs", "efivarfs",
    "nsfs", "fuse.portal", "fuse.gvfsd-fuse", "binfmt_misc", "overlay",
}

VIRTUAL_PATH_PREFIXES = (
    "/proc",
    "/sys",
    "/dev",
    "/run",
    "/snap",
    "/var/lib/snapd/snaps",
)


def get_virtual_mount_points() -> set:
    """Reads /proc/mounts to identify virtual/pseudo mount points to skip."""
    virtual_mounts = set(VIRTUAL_PATH_PREFIXES)
    try:
        with open("/proc/mounts", "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 3:
                    mount_point = parts[1].replace("\\040", " ")
                    fs_type = parts[2]
                    if fs_type in VIRTUAL_FS_TYPES and mount_point != "/":
                        virtual_mounts.add(mount_point.rstrip("/") or "/")
    except Exception:
        pass
    return virtual_mounts


# ==============================================================================
# Data Structures for Scanned Tree & Squarified Treemap
# ==============================================================================

@dataclass
class ScanNode:
    name: str
    path: str
    size: int = 0
    is_dir: bool = False
    mtime: float = 0.0
    children: List["ScanNode"] = field(default_factory=list)
    parent: Optional["ScanNode"] = field(default=None, repr=False)
    ext: str = ""
    category: str = "Folder"
    color: str = "#3b4252"
    file_count: int = 0
    dir_count: int = 0

    def to_dict(self, max_depth: int = 6, max_children_per_dir: int = 250) -> dict:
        sorted_children = sorted(self.children, key=lambda c: c.size, reverse=True)
        kept_children = sorted_children[:max_children_per_dir] if max_depth > 0 else []
        remainder_size = sum(c.size for c in sorted_children[max_children_per_dir:]) if max_depth > 0 else 0

        child_dicts = [c.to_dict(max_depth - 1, max_children_per_dir) for c in kept_children]
        if remainder_size > 0:
            other_count = len(sorted_children) - max_children_per_dir
            child_dicts.append({
                "n": f"[{other_count} smaller items]",
                "p": self.path,
                "s": remainder_size,
                "d": False,
                "m": self.mtime,
                "c": [],
                "fc": other_count,
                "dc": 0,
            })

        return {
            "n": self.name,
            "p": self.path,
            "s": self.size,
            "d": self.is_dir,
            "m": self.mtime,
            "c": child_dicts,
            "fc": self.file_count,
            "dc": self.dir_count,
        }

    @staticmethod
    def from_dict(data: dict, parent: Optional["ScanNode"] = None) -> "ScanNode":
        name = data["n"]
        is_dir = data["d"]
        if is_dir:
            ext, cat, col = "", "Folder", "#3b4252"
        else:
            ext, cat, col = classify_extension(name)
        node = ScanNode(
            name=name,
            path=data["p"],
            size=data["s"],
            is_dir=is_dir,
            mtime=data.get("m", 0.0),
            parent=parent,
            ext=ext,
            category=cat,
            color=col,
            file_count=data.get("fc", 0 if is_dir else 1),
            dir_count=data.get("dc", 0),
        )
        node.children = [ScanNode.from_dict(ch, parent=node) for ch in data.get("c", [])]
        return node


# ==============================================================================
# Filtering & Search Matching Helpers (Hebrew & English Case-Insensitive)
# ==============================================================================

def node_matches_query(node: ScanNode, query: str) -> bool:
    if not query:
        return True
    q = query.strip().lower()
    name_l = node.name.lower()
    ext_l = node.ext.lower()
    cat_l = node.category.lower()

    if any(ch in q for ch in ("*", "?", "[")):
        if fnmatch.fnmatch(name_l, q) or (node.ext and fnmatch.fnmatch(ext_l, q)):
            return True
    return (q in name_l) or (q in ext_l) or (q in cat_l)


def node_or_descendant_matches(node: ScanNode, query: str) -> bool:
    if not query:
        return True
    if node_matches_query(node, query):
        return True
    if node.is_dir:
        for ch in node.children:
            if node_or_descendant_matches(ch, query):
                return True
    return False


def build_filtered_isolated_tree(
    source_node: ScanNode, query: str
) -> Tuple[Optional[ScanNode], int, int]:
    if not query:
        return source_node, source_node.file_count, source_node.size

    match_files = 0
    match_bytes = 0

    def filter_recursive(curr: ScanNode, parent_ref: Optional[ScanNode]) -> Optional[ScanNode]:
        nonlocal match_files, match_bytes
        if not curr.is_dir:
            if node_matches_query(curr, query):
                match_files += 1
                match_bytes += curr.size
                return ScanNode(
                    name=curr.name,
                    path=curr.path,
                    size=curr.size,
                    is_dir=False,
                    mtime=curr.mtime,
                    parent=parent_ref,
                    ext=curr.ext,
                    category=curr.category,
                    color=curr.color,
                    file_count=1,
                    dir_count=0,
                )
            return None

        kept_children: List[ScanNode] = []
        new_dir = ScanNode(
            name=curr.name,
            path=curr.path,
            size=0,
            is_dir=True,
            mtime=curr.mtime,
            parent=parent_ref,
            ext=curr.ext,
            category=curr.category,
            color=curr.color,
        )
        for ch in curr.children:
            filtered_ch = filter_recursive(ch, new_dir)
            if filtered_ch:
                kept_children.append(filtered_ch)

        folder_itself_matches = node_matches_query(curr, query)
        if kept_children or folder_itself_matches:
            new_dir.children = kept_children
            new_dir.size = sum(c.size for c in kept_children)
            new_dir.file_count = sum(c.file_count for c in kept_children)
            new_dir.dir_count = len(kept_children)
            return new_dir
        return None

    res_root = filter_recursive(source_node, None)
    return res_root, match_files, match_bytes


# ==============================================================================
# High-Speed Disk Scanner
# ==============================================================================

class FastDiskScanner:
    def __init__(self, filter_virtual: bool = True, progress_cb=None, cancel_check=None):
        self.filter_virtual = filter_virtual
        self.virtual_mounts = get_virtual_mount_points() if filter_virtual else set()
        self.progress_cb = progress_cb
        self.cancel_check = cancel_check
        self.files_scanned = 0
        self.dirs_scanned = 0
        self.bytes_scanned = 0
        self.permission_errors = 0

    def _should_skip_dir(self, path: str) -> bool:
        if not self.filter_virtual:
            return False
        norm = path.rstrip("/")
        if norm in self.virtual_mounts:
            return True
        for prefix in VIRTUAL_PATH_PREFIXES:
            if norm == prefix or norm.startswith(prefix + "/"):
                return True
        return False

    def scan(self, root_path: str) -> ScanNode:
        root_path = os.path.abspath(root_path)
        root_name = os.path.basename(root_path.rstrip("/")) or "/"
        try:
            st = os.stat(root_path, follow_symlinks=False)
            mtime = st.st_mtime
        except Exception:
            mtime = 0.0

        root_node = ScanNode(
            name=root_name,
            path=root_path,
            is_dir=True,
            mtime=mtime,
        )
        self._scan_recursive(root_node)
        return root_node

    def _scan_recursive(self, dir_node: ScanNode) -> None:
        if self.cancel_check and self.cancel_check():
            return

        self.dirs_scanned += 1
        if self.progress_cb and (self.dirs_scanned % 40 == 0):
            self.progress_cb(self.files_scanned, self.bytes_scanned, dir_node.path)

        total_size = 0
        total_files = 0
        total_dirs = 0
        children: List[ScanNode] = []

        try:
            with os.scandir(dir_node.path) as it:
                for entry in it:
                    if self.cancel_check and self.cancel_check():
                        break
                    try:
                        if entry.is_symlink():
                            continue
                        entry_path = entry.path
                        st = entry.stat(follow_symlinks=False)
                        if stat.S_ISDIR(st.st_mode):
                            if self._should_skip_dir(entry_path):
                                continue
                            sub_node = ScanNode(
                                name=entry.name,
                                path=entry_path,
                                is_dir=True,
                                mtime=st.st_mtime,
                                parent=dir_node,
                            )
                            self._scan_recursive(sub_node)
                            if sub_node.size > 0:
                                children.append(sub_node)
                                total_size += sub_node.size
                                total_files += sub_node.file_count
                                total_dirs += 1 + sub_node.dir_count
                        elif stat.S_ISREG(st.st_mode):
                            actual_size = st.st_size
                            if hasattr(st, "st_blocks") and st.st_blocks > 0:
                                alloc_size = st.st_blocks * 512
                                if alloc_size < actual_size:
                                    actual_size = alloc_size

                            ext, cat, col = classify_extension(entry.name)
                            f_node = ScanNode(
                                name=entry.name,
                                path=entry_path,
                                size=actual_size,
                                is_dir=False,
                                mtime=st.st_mtime,
                                parent=dir_node,
                                ext=ext,
                                category=cat,
                                color=col,
                                file_count=1,
                            )
                            children.append(f_node)
                            total_size += actual_size
                            total_files += 1
                            self.files_scanned += 1
                            self.bytes_scanned += actual_size
                    except PermissionError:
                        self.permission_errors += 1
                    except OSError:
                        continue
        except PermissionError:
            self.permission_errors += 1
        except OSError:
            pass

        children.sort(key=lambda c: c.size, reverse=True)
        if len(children) > 350:
            kept = children[:350]
            rem_children = children[350:]
            rem_size = sum(c.size for c in rem_children)
            if rem_size > 0:
                kept.append(
                    ScanNode(
                        name=f"[{len(rem_children)} smaller files]",
                        path=dir_node.path,
                        size=rem_size,
                        is_dir=False,
                        mtime=dir_node.mtime,
                        parent=dir_node,
                        ext="[Grouped]",
                        category="Other Files",
                        color=DEFAULT_CATEGORY_COLOR,
                        file_count=len(rem_children),
                    )
                )
            children = kept

        dir_node.children = children
        dir_node.size = total_size
        dir_node.file_count = total_files
        dir_node.dir_count = total_dirs


def run_admin_scan_worker(target_path: str, filter_virtual: bool) -> int:
    def report_progress(files: int, num_bytes: int, current_path: str):
        safe_path = current_path.replace("\n", " ")
        sys.stdout.write(f"PROGRESS\t{files}\t{num_bytes}\t{safe_path}\n")
        sys.stdout.flush()

    scanner = FastDiskScanner(filter_virtual=filter_virtual, progress_cb=report_progress)
    tree = scanner.scan(target_path)
    payload_dict = {
        "tree": tree.to_dict(max_depth=7, max_children_per_dir=250),
        "files_scanned": scanner.files_scanned,
        "dirs_scanned": scanner.dirs_scanned,
        "permission_errors": scanner.permission_errors,
    }
    raw_json = json.dumps(payload_dict, ensure_ascii=False).encode("utf-8")
    compressed = base64.b64encode(zlib.compress(raw_json, level=6)).decode("ascii")
    sys.stdout.write(f"RESULT\t{compressed}\n")
    sys.stdout.flush()
    return 0


# ==============================================================================
# Squarified Treemap Layout Algorithm
# ==============================================================================

@dataclass
class TreemapRect:
    node: ScanNode
    x: float
    y: float
    w: float
    h: float
    depth: int = 0
    is_group_header: bool = False
    is_matching: bool = True


def squarify_layout(
    items: List[ScanNode],
    x: float,
    y: float,
    w: float,
    h: float,
) -> List[Tuple[ScanNode, float, float, float, float]]:
    valid_items = [it for it in items if it.size > 0]
    if not valid_items or w <= 1.0 or h <= 1.0:
        return []

    total_size = sum(it.size for it in valid_items)
    if total_size <= 0:
        return []

    total_area = w * h
    scaled = [(it, (it.size / total_size) * total_area) for it in valid_items]

    results: List[Tuple[ScanNode, float, float, float, float]] = []
    cur_x, cur_y, cur_w, cur_h = x, y, w, h

    def worst_ratio(row: List[Tuple[ScanNode, float]], side: float) -> float:
        if not row or side <= 0:
            return float("inf")
        areas = [a for _, a in row]
        s = sum(areas)
        if s <= 0:
            return float("inf")
        r_max = max(areas)
        r_min = min(areas)
        if r_min <= 0:
            return float("inf")
        s2 = s * s
        side2 = side * side
        return max((side2 * r_max) / s2, s2 / (side2 * r_min))

    def layout_row(row: List[Tuple[ScanNode, float]]):
        nonlocal cur_x, cur_y, cur_w, cur_h
        row_area = sum(a for _, a in row)
        if row_area <= 0:
            return
        if cur_w >= cur_h:
            row_w = row_area / cur_h if cur_h > 0 else 0
            ry = cur_y
            for it, a in row:
                rh = a / row_w if row_w > 0 else 0
                results.append((it, cur_x, ry, row_w, rh))
                ry += rh
            cur_x += row_w
            cur_w = max(0.0, cur_w - row_w)
        else:
            row_h = row_area / cur_w if cur_w > 0 else 0
            rx = cur_x
            for it, a in row:
                rw = a / row_h if row_h > 0 else 0
                results.append((it, rx, cur_y, rw, row_h))
                rx += rw
            cur_y += row_h
            cur_h = max(0.0, cur_h - row_h)

    current_row: List[Tuple[ScanNode, float]] = []
    for item_pair in scaled:
        short_side = min(cur_w, cur_h)
        if short_side <= 0:
            break
        if not current_row:
            current_row.append(item_pair)
        else:
            if worst_ratio(current_row + [item_pair], short_side) <= worst_ratio(current_row, short_side):
                current_row.append(item_pair)
            else:
                layout_row(current_row)
                current_row = [item_pair]

    if current_row:
        layout_row(current_row)

    return results


def build_filetype_grouped_root(source_node: ScanNode) -> ScanNode:
    ext_groups: Dict[str, List[ScanNode]] = {}

    def collect_files(node: ScanNode):
        if not node.is_dir:
            ext_key = node.ext if node.ext else "[No Ext]"
            ext_groups.setdefault(ext_key, []).append(node)
        else:
            for ch in node.children:
                collect_files(ch)

    collect_files(source_node)

    virtual_root = ScanNode(
        name=f"{source_node.name} (By File Types)",
        path=source_node.path,
        size=source_node.size,
        is_dir=True,
        mtime=source_node.mtime,
        file_count=source_node.file_count,
        dir_count=len(ext_groups),
    )

    group_nodes: List[ScanNode] = []
    for ext_key, file_list in ext_groups.items():
        group_size = sum(f.size for f in file_list)
        if group_size <= 0:
            continue
        sample = file_list[0]
        cat_name = sample.category
        color = sample.color
        file_list_sorted = sorted(file_list, key=lambda f: f.size, reverse=True)

        g_node = ScanNode(
            name=f"{ext_key}  ({cat_name})",
            path=source_node.path,
            size=group_size,
            is_dir=True,
            mtime=source_node.mtime,
            parent=virtual_root,
            ext=ext_key,
            category=cat_name,
            color=color,
            file_count=len(file_list_sorted),
            dir_count=0,
        )
        g_node.children = file_list_sorted[:250]
        group_nodes.append(g_node)

    group_nodes.sort(key=lambda g: g.size, reverse=True)
    virtual_root.children = group_nodes
    return virtual_root


# ==============================================================================
# Custom Desktop Icon Generation (SVG & High-Res PNG)
# ==============================================================================

CUSTOM_ICON_SVG = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 256 256" width="256" height="256">
  <defs>
    <linearGradient id="bgGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#1f2937" />
      <stop offset="100%" stop-color="#0b0f17" />
    </linearGradient>
    <linearGradient id="borderGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#00f5d4" />
      <stop offset="50%" stop-color="#388bfd" />
      <stop offset="100%" stop-color="#8338ec" />
    </linearGradient>
    <linearGradient id="tileBlue" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#4ea8de" />
      <stop offset="100%" stop-color="#1d4ed8" />
    </linearGradient>
    <linearGradient id="tileRed" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#ff4d6d" />
      <stop offset="100%" stop-color="#c9184a" />
    </linearGradient>
    <linearGradient id="tileGreen" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#52b788" />
      <stop offset="100%" stop-color="#1b4332" />
    </linearGradient>
    <linearGradient id="tileAmber" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#ffb703" />
      <stop offset="100%" stop-color="#fb8500" />
    </linearGradient>
    <linearGradient id="tilePurple" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#9d4edd" />
      <stop offset="100%" stop-color="#5a189a" />
    </linearGradient>
    <linearGradient id="tileCyan" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#48cae4" />
      <stop offset="100%" stop-color="#0077b6" />
    </linearGradient>
    <filter id="glow" x="-20%" y="-20%" width="140%" height="140%">
      <feGaussianBlur stdDeviation="8" result="blur" />
      <feComposite in="SourceGraphic" in2="blur" operator="over" />
    </filter>
  </defs>

  <!-- Base Squircle with Glowing Neon Border -->
  <rect x="8" y="8" width="240" height="240" rx="54" ry="54" fill="url(#bgGrad)" stroke="url(#borderGrad)" stroke-width="5" filter="url(#glow)"/>
  <rect x="8" y="8" width="240" height="240" rx="54" ry="54" fill="url(#bgGrad)" stroke="url(#borderGrad)" stroke-width="5"/>

  <!-- Top Status / Disk Header Strip -->
  <rect x="22" y="22" width="212" height="24" rx="8" fill="#161b22" stroke="#30363d" stroke-width="1.5" />
  <circle cx="38" cy="34" r="5" fill="#00f5d4" />
  <circle cx="54" cy="34" r="5" fill="#388bfd" />
  <circle cx="70" cy="34" r="5" fill="#f72585" />
  <rect x="92" y="31" width="85" height="6" rx="3" fill="#30363d" />

  <!-- Stylized WizTree Treemap Mosaic -->
  <g transform="translate(22, 54)">
    <!-- Big Blue Block (Large Folders) -->
    <rect x="0" y="0" width="112" height="106" rx="8" fill="url(#tileBlue)" stroke="#0f172a" stroke-width="2"/>
    <!-- Red Block (Videos/ISOs) -->
    <rect x="116" y="0" width="96" height="58" rx="8" fill="url(#tileRed)" stroke="#0f172a" stroke-width="2"/>
    <!-- Green Block (Archives) -->
    <rect x="116" y="62" width="96" height="44" rx="8" fill="url(#tileGreen)" stroke="#0f172a" stroke-width="2"/>
    <!-- Amber Block (Documents/Images) -->
    <rect x="0" y="110" width="70" height="70" rx="8" fill="url(#tileAmber)" stroke="#0f172a" stroke-width="2"/>
    <!-- Purple Block (Code/Apps) -->
    <rect x="74" y="110" width="78" height="70" rx="8" fill="url(#tilePurple)" stroke="#0f172a" stroke-width="2"/>
    <!-- Cyan Small Blocks -->
    <rect x="156" y="110" width="56" height="33" rx="6" fill="url(#tileCyan)" stroke="#0f172a" stroke-width="2"/>
    <rect x="156" y="147" width="26" height="33" rx="6" fill="#00f5d4" stroke="#0f172a" stroke-width="2"/>
    <rect x="186" y="147" width="26" height="33" rx="6" fill="#ff70a6" stroke="#0f172a" stroke-width="2"/>
  </g>

  <!-- Glossy Diagonal Light Sheen -->
  <path d="M 24 70 Q 128 35 232 70 L 232 40 Q 128 20 24 40 Z" fill="#ffffff" opacity="0.12" />
</svg>
"""


def install_custom_icons() -> str:
    """Installs the custom high-res WizTree icon to the user's icon themes."""
    icons_dir = os.path.expanduser("~/.local/share/icons/hicolor/scalable/apps")
    os.makedirs(icons_dir, exist_ok=True)
    svg_path = os.path.join(icons_dir, "wiztree-ubuntu.svg")
    with open(svg_path, "w", encoding="utf-8") as f:
        f.write(CUSTOM_ICON_SVG.strip())

    # Try rendering a 256x256 PNG version via Pillow for desktops that prefer raster icons
    png_path = os.path.join(os.path.expanduser("~/.local/share/icons/hicolor/256x256/apps"), "wiztree-ubuntu.png")
    os.makedirs(os.path.dirname(png_path), exist_ok=True)
    try:
        from PIL import Image, ImageDraw
        img = Image.new("RGBA", (256, 256), (0, 0, 0, 0))
        draw = ImageDraw.Draw(img)
        # Draw squircle background
        draw.rounded_rectangle([8, 8, 248, 248], radius=54, fill=(17, 21, 28, 255), outline=(0, 245, 212, 255), width=4)
        draw.rounded_rectangle([22, 22, 234, 46], radius=8, fill=(22, 27, 34, 255), outline=(48, 54, 61, 255), width=2)
        draw.ellipse([34, 30, 44, 40], fill=(0, 245, 212, 255))
        draw.ellipse([50, 30, 60, 40], fill=(56, 139, 253, 255))
        draw.ellipse([66, 30, 76, 40], fill=(247, 37, 133, 255))
        # Treemap tiles
        draw.rounded_rectangle([22, 54, 134, 160], radius=8, fill=(58, 134, 255, 255), outline=(15, 23, 42, 255), width=2)
        draw.rounded_rectangle([138, 54, 234, 112], radius=8, fill=(230, 57, 70, 255), outline=(15, 23, 42, 255), width=2)
        draw.rounded_rectangle([138, 116, 234, 160], radius=8, fill=(6, 214, 160, 255), outline=(15, 23, 42, 255), width=2)
        draw.rounded_rectangle([22, 164, 92, 234], radius=8, fill=(244, 162, 97, 255), outline=(15, 23, 42, 255), width=2)
        draw.rounded_rectangle([96, 164, 174, 234], radius=8, fill=(155, 93, 229, 255), outline=(15, 23, 42, 255), width=2)
        draw.rounded_rectangle([178, 164, 234, 197], radius=6, fill=(0, 187, 249, 255), outline=(15, 23, 42, 255), width=2)
        draw.rounded_rectangle([178, 201, 204, 234], radius=6, fill=(0, 245, 212, 255), outline=(15, 23, 42, 255), width=2)
        draw.rounded_rectangle([208, 201, 234, 234], radius=6, fill=(255, 112, 166, 255), outline=(15, 23, 42, 255), width=2)
        img.save(png_path, "PNG")
    except Exception:
        pass

    return svg_path


# ==============================================================================
# Desktop Shortcut Creator ("עמוד הבית / שולחן העבודה")
# ==============================================================================

def get_desktop_directories() -> List[str]:
    dirs = []
    try:
        out = subprocess.check_output(["xdg-user-dir", "DESKTOP"], stderr=subprocess.DEVNULL, text=True).strip()
        if out and os.path.isdir(out):
            dirs.append(out)
    except Exception:
        pass

    home = os.path.expanduser("~")
    for cand in ("Desktop", "שולחן העבודה"):
        p = os.path.join(home, cand)
        if os.path.isdir(p) and p not in dirs:
            dirs.append(p)

    if not dirs:
        fallback = os.path.join(home, "Desktop")
        os.makedirs(fallback, exist_ok=True)
        dirs.append(fallback)
    return dirs


def create_desktop_shortcut() -> Tuple[bool, str]:
    bin_dir = os.path.expanduser("~/.local/bin")
    os.makedirs(bin_dir, exist_ok=True)
    target_script = os.path.join(bin_dir, "wiztree_ubuntu.py")

    if not os.path.exists(target_script) or not os.path.samefile(os.path.abspath(__file__), target_script):
        shutil.copy2(os.path.abspath(__file__), target_script)
        os.chmod(target_script, 0o755)

    icon_path = install_custom_icons()

    desktop_content = f"""[Desktop Entry]
Version=1.0
Name=WizTree Ubuntu
GenericName=Disk Space Treemap Analyzer
Comment=High-Speed Visual Treemap Disk Space Analyzer
Exec={sys.executable} {target_script} %F
Icon={icon_path}
Terminal=false
Type=Application
Categories=System;Filesystem;Utility;
Keywords=disk;space;treemap;wiztree;analyzer;storage;
StartupNotify=true
"""

    created_paths = []
    desktop_dirs = get_desktop_directories()

    for d_dir in desktop_dirs:
        shortcut_file = os.path.join(d_dir, "wiztree-ubuntu.desktop")
        try:
            with open(shortcut_file, "w", encoding="utf-8") as f:
                f.write(desktop_content)
            os.chmod(shortcut_file, 0o755)
            # Mark trusted for GNOME Desktop Icons NG
            subprocess.run(["gio", "set", shortcut_file, "metadata::trusted", "true"], stderr=subprocess.DEVNULL)
            created_paths.append(shortcut_file)
        except Exception as e:
            print(f"[!] Warning writing shortcut to {shortcut_file}: {e}")

    apps_dir = os.path.expanduser("~/.local/share/applications")
    os.makedirs(apps_dir, exist_ok=True)
    menu_file = os.path.join(apps_dir, "wiztree-ubuntu.desktop")
    try:
        with open(menu_file, "w", encoding="utf-8") as f:
            f.write(desktop_content)
        os.chmod(menu_file, 0o755)
        subprocess.run(["update-desktop-database", apps_dir], stderr=subprocess.DEVNULL)
        created_paths.append(menu_file)
    except Exception:
        pass

    if created_paths:
        return True, "Shortcut created with custom icon at:\n" + "\n".join(created_paths)
    return False, "Failed to create desktop shortcut."


# ==============================================================================
# File Shredder Launcher Bridge (~/.local/bin/file_shredder_gui.py)
# ==============================================================================

SHREDDER_WRAPPER_CODE = """
import os, sys, tkinter.filedialog as fd
target = sys.argv[1]
target_dir = target if os.path.isdir(target) else os.path.dirname(target)
os.chdir(target_dir)

_orig_askdir = fd.askdirectory
_orig_askfile = fd.askopenfilename
_orig_askfiles = fd.askopenfilenames
_used_once = False

def _smart_askdir(**kw):
    global _used_once
    if not _used_once:
        _used_once = True
        return target_dir
    kw.setdefault("initialdir", target_dir)
    return _orig_askdir(**kw)

def _smart_askfile(**kw):
    global _used_once
    if not _used_once and os.path.isfile(target):
        _used_once = True
        return target
    kw.setdefault("initialdir", target_dir)
    return _orig_askfile(**kw)

def _smart_askfiles(**kw):
    global _used_once
    if not _used_once and os.path.isfile(target):
        _used_once = True
        return (target,)
    kw.setdefault("initialdir", target_dir)
    return _orig_askfiles(**kw)

fd.askdirectory = _smart_askdir
fd.askopenfilename = _smart_askfile
fd.askopenfilenames = _smart_askfiles

shredder_path = os.path.expanduser("~/.local/bin/file_shredder_gui.py")
sys.argv = [shredder_path, target]
with open(shredder_path, "rb") as f:
    code = compile(f.read(), shredder_path, "exec")
exec(code, {"__name__": "__main__", "__file__": shredder_path})
"""


def launch_external_file_shredder(target_path: str) -> Tuple[bool, str]:
    shredder_path = os.path.expanduser("~/.local/bin/file_shredder_gui.py")
    target_path = os.path.abspath(target_path)
    target_dir = target_path if os.path.isdir(target_path) else os.path.dirname(target_path)

    if os.path.exists(shredder_path):
        subprocess.Popen(
            [sys.executable, "-c", SHREDDER_WRAPPER_CODE, target_path],
            cwd=target_dir,
        )
        return (
            True,
            f"Launched File Shredder pre-linked to:\n{target_path}\n"
            "(Clicking 'Select Folder/File' in File Shredder will automatically load this path!)",
        )
    return (
        False,
        f"~/.local/bin/file_shredder_gui.py was not found.\n"
        "You can use the built-in 'Quick Overwrite & Shred' option right now.",
    )


def builtin_secure_shred(target_paths: List[str], passes: int = 3) -> Tuple[bool, str]:
    if isinstance(target_paths, str):
        target_paths = [target_paths]

    def shred_single_file(fp: str):
        if os.path.islink(fp):
            os.unlink(fp)
            return
        size = os.path.getsize(fp)
        with open(fp, "r+b", buffering=0) as f:
            chunk_size = 1024 * 1024
            for p in range(passes):
                f.seek(0)
                remaining = size
                while remaining > 0:
                    n = min(chunk_size, remaining)
                    data = os.urandom(n) if p < passes - 1 else (b"\x00" * n)
                    f.write(data)
                    remaining -= n
                f.flush()
                os.fsync(f.fileno())
        parent = os.path.dirname(fp)
        scrubbed_name = os.path.join(parent, "000000000000.tmp")
        try:
            os.replace(fp, scrubbed_name)
            os.remove(scrubbed_name)
        except Exception:
            os.remove(fp)

    success_count = 0
    errors = []

    for path in target_paths:
        tp = os.path.abspath(path)
        try:
            if os.path.isfile(tp) or os.path.islink(tp):
                shred_single_file(tp)
            elif os.path.isdir(tp):
                for root, dirs, files in os.walk(tp, topdown=False):
                    for name in files:
                        shred_single_file(os.path.join(root, name))
                    for name in dirs:
                        os.rmdir(os.path.join(root, name))
                os.rmdir(tp)
            success_count += 1
        except PermissionError:
            if os.path.isfile(tp):
                res = subprocess.run(["pkexec", "shred", "-f", "-u", "-z", "-n", str(passes), tp])
            else:
                res = subprocess.run(["pkexec", "rm", "-rf", tp])
            if res.returncode == 0:
                success_count += 1
            else:
                errors.append(f"Permission denied for {os.path.basename(tp)}")
        except Exception as e:
            errors.append(f"{os.path.basename(tp)}: {e}")

    if success_count == len(target_paths):
        return True, f"Successfully shredded {success_count} item(s)."
    return False, f"Shredded {success_count}/{len(target_paths)} items. Errors: " + "; ".join(errors)


# ==============================================================================
# PyQt6 Graphical User Interface with Windows-Style Rubber-Band Selection
# ==============================================================================

def run_gui(initial_path: Optional[str] = None):
    try:
        from PyQt6.QtCore import Qt, QRectF, QPointF, QThread, pyqtSignal, QSize, QTimer
        from PyQt6.QtGui import (
            QColor, QPainter, QPen, QBrush, QLinearGradient, QFont,
            QFontMetrics, QPixmap, QAction, QCursor, QGuiApplication, QIcon
        )
        from PyQt6.QtWidgets import (
            QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
            QPushButton, QLabel, QFileDialog, QSplitter, QFrame, QProgressBar,
            QMenu, QMessageBox, QTableWidget, QTableWidgetItem, QHeaderView,
            QTextEdit, QCheckBox, QComboBox, QStackedWidget, QLineEdit, QSizePolicy
        )
    except ImportError:
        print("[!] PyQt6 is required for the graphical interface.")
        print("    Run:  python3 wiztree_ubuntu.py --install")
        print("    Or:   sudo apt install -y python3-pyqt6")
        sys.exit(1)

    QGuiApplication.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
    )

    class ScanWorkerThread(QThread):
        progress = pyqtSignal(int, int, str)
        finished_scan = pyqtSignal(object, int, int, int, bool)
        failed_scan = pyqtSignal(str)

        def __init__(self, target_path: str, filter_virtual: bool, as_admin: bool = False):
            super().__init__()
            self.target_path = target_path
            self.filter_virtual = filter_virtual
            self.as_admin = as_admin
            self._cancelled = False

        def cancel(self):
            self._cancelled = True

        def run(self):
            if not self.as_admin:
                scanner = FastDiskScanner(
                    filter_virtual=self.filter_virtual,
                    progress_cb=lambda f, b, p: self.progress.emit(f, b, p),
                    cancel_check=lambda: self._cancelled,
                )
                tree = scanner.scan(self.target_path)
                self.finished_scan.emit(
                    tree,
                    scanner.files_scanned,
                    scanner.dirs_scanned,
                    scanner.permission_errors,
                    False,
                )
            else:
                script_path = os.path.abspath(__file__)
                fv_flag = "1" if self.filter_virtual else "0"
                cmd = ["pkexec", sys.executable, script_path, "--admin-scan-worker", self.target_path, fv_flag]
                try:
                    proc = subprocess.Popen(
                        cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        bufsize=1,
                    )
                    result_b64 = None
                    for line in proc.stdout:
                        if self._cancelled:
                            proc.terminate()
                            return
                        line = line.strip()
                        if line.startswith("PROGRESS\t"):
                            parts = line.split("\t", 3)
                            if len(parts) == 4:
                                self.progress.emit(int(parts[1]), int(parts[2]), parts[3])
                        elif line.startswith("RESULT\t"):
                            result_b64 = line.split("\t", 1)[1]

                    proc.wait()
                    if proc.returncode != 0 or not result_b64:
                        err_msg = proc.stderr.read().strip() if proc.stderr else ""
                        self.failed_scan.emit(
                            err_msg or "Administrator authentication was canceled or failed."
                        )
                        return

                    raw_bytes = zlib.decompress(base64.b64decode(result_b64))
                    payload = json.loads(raw_bytes.decode("utf-8"))
                    tree = ScanNode.from_dict(payload["tree"])
                    self.finished_scan.emit(
                        tree,
                        payload.get("files_scanned", 0),
                        payload.get("dirs_scanned", 0),
                        payload.get("permission_errors", 0),
                        True,
                    )
                except Exception as e:
                    self.failed_scan.emit(str(e))

    class TreemapCanvas(QWidget):
        """High-DPI Cushioned Squarified Treemap with Windows-Style Rubber-Band Multi-Selection."""
        nodes_selected = pyqtSignal(list)
        node_zoomed = pyqtSignal(object)
        context_action_requested = pyqtSignal(list, QPointF)

        def __init__(self):
            super().__init__()
            self.setMouseTracking(True)
            self.setMinimumSize(480, 340)
            self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)

            self.current_root: Optional[ScanNode] = None
            self.rects: List[TreemapRect] = []
            self.hovered_node: Optional[ScanNode] = None
            self.selected_nodes: List[ScanNode] = []
            self.color_by_folder: bool = False
            self.filter_query: str = ""

            # Windows-style translucent blue rubber-band marquee selection state
            self.is_rubber_banding: bool = False
            self.drag_start_pos: QPointF = QPointF()
            self.drag_current_pos: QPointF = QPointF()

        def set_root_node(
            self,
            node: Optional[ScanNode],
            color_by_folder: bool = False,
            filter_query: str = "",
        ):
            self.current_root = node
            self.color_by_folder = color_by_folder
            self.filter_query = filter_query.strip().lower()
            self.hovered_node = None
            self.selected_nodes = [node] if node else []
            self.is_rubber_banding = False
            self._recompute_layout()
            self.update()

        def set_filter_query(self, query: str):
            self.filter_query = query.strip().lower()
            self._recompute_layout()
            self.update()

        def set_selected_nodes(self, nodes: List[ScanNode]):
            self.selected_nodes = list(nodes)
            self.update()

        def resizeEvent(self, event):
            super().resizeEvent(event)
            self._recompute_layout()

        def _recompute_layout(self):
            self.rects.clear()
            if not self.current_root or self.current_root.size <= 0:
                return

            margin = 6.0
            w = max(0.0, float(self.width()) - 2 * margin)
            h = max(0.0, float(self.height()) - 2 * margin)
            if w <= 10 or h <= 10:
                return

            top_children = [c for c in self.current_root.children if c.size > 0]
            if not top_children:
                return

            top_layout = squarify_layout(top_children, margin, margin, w, h)
            folder_palette = [
                "#3a86ff", "#8338ec", "#ff006e", "#fb5607",
                "#ffbe0b", "#06d6a0", "#118ab2", "#ef476f",
            ]

            q = self.filter_query

            for idx, (child, cx, cy, cw, ch) in enumerate(top_layout):
                if cw < 1.5 or ch < 1.5:
                    continue

                if self.color_by_folder:
                    child_folder_color = folder_palette[idx % len(folder_palette)]
                else:
                    child_folder_color = child.color

                child_matches = node_or_descendant_matches(child, q) if q else True

                if child.is_dir and child.children and cw >= 36 and ch >= 36:
                    header_h = 20.0 if ch >= 52 else 14.0
                    self.rects.append(
                        TreemapRect(
                            node=child,
                            x=cx,
                            y=cy,
                            w=cw,
                            h=ch,
                            depth=0,
                            is_group_header=True,
                            is_matching=child_matches,
                        )
                    )
                    inner_pad = 3.0
                    ix = cx + inner_pad
                    iy = cy + header_h + 1.0
                    iw = max(0.0, cw - 2 * inner_pad)
                    ih = max(0.0, ch - header_h - inner_pad - 1.0)
                    sub_layout = squarify_layout(child.children, ix, iy, iw, ih)
                    for sub_node, sx, sy, sw, sh in sub_layout:
                        if sw < 1.2 or sh < 1.2:
                            continue
                        if self.color_by_folder and sub_node.is_dir:
                            sub_node.color = child_folder_color
                        sub_matches = node_or_descendant_matches(sub_node, q) if q else True
                        self.rects.append(
                            TreemapRect(
                                node=sub_node,
                                x=sx,
                                y=sy,
                                w=sw,
                                h=sh,
                                depth=1,
                                is_group_header=False,
                                is_matching=sub_matches,
                            )
                        )
                else:
                    if self.color_by_folder and child.is_dir:
                        child.color = child_folder_color
                    self.rects.append(
                        TreemapRect(
                            node=child,
                            x=cx,
                            y=cy,
                            w=cw,
                            h=ch,
                            depth=0,
                            is_group_header=False,
                            is_matching=child_matches,
                        )
                    )

        def _rect_at(self, pos: QPointF) -> Optional[TreemapRect]:
            px, py = pos.x(), pos.y()
            for r in reversed(self.rects):
                if r.x <= px <= r.x + r.w and r.y <= py <= r.y + r.h:
                    return r
            return None

        def _get_selection_box(self) -> QRectF:
            p1 = self.drag_start_pos
            p2 = self.drag_current_pos
            return QRectF(
                min(p1.x(), p2.x()),
                min(p1.y(), p2.y()),
                abs(p1.x() - p2.x()),
                abs(p1.y() - p2.y()),
            )

        def mousePressEvent(self, event):
            pos = event.position()
            if event.button() == Qt.MouseButton.LeftButton:
                self.drag_start_pos = pos
                self.drag_current_pos = pos
                self.is_rubber_banding = False
            elif event.button() == Qt.MouseButton.RightButton:
                r = self._rect_at(pos)
                clicked_node = r.node if r else self.current_root
                if clicked_node:
                    if clicked_node not in self.selected_nodes:
                        self.selected_nodes = [clicked_node]
                        self.nodes_selected.emit(self.selected_nodes)
                        self.update()
                    self.context_action_requested.emit(self.selected_nodes, event.globalPosition())

        def mouseMoveEvent(self, event):
            pos = event.position()

            if event.buttons() & Qt.MouseButton.LeftButton:
                dist = math.hypot(pos.x() - self.drag_start_pos.x(), pos.y() - self.drag_start_pos.y())
                if dist >= 6.0:
                    self.is_rubber_banding = True
                    self.drag_current_pos = pos
                    sel_box = self._get_selection_box()

                    # Find all leaf or top items that intersect the blue box
                    matched_nodes = []
                    seen_nodes = set()
                    for r in self.rects:
                        if not r.is_group_header:
                            b_rect = QRectF(r.x, r.y, r.w, r.h)
                            if b_rect.intersects(sel_box):
                                if r.node not in seen_nodes:
                                    seen_nodes.add(r.node)
                                    matched_nodes.append(r.node)

                    self.selected_nodes = matched_nodes
                    self.nodes_selected.emit(self.selected_nodes)
                    self.update()
                    return

            # Normal Hover tooltip logic
            r = self._rect_at(pos)
            new_hover = r.node if r else None
            if new_hover is not self.hovered_node:
                self.hovered_node = new_hover
                if new_hover and self.current_root and self.current_root.size > 0:
                    pct = (new_hover.size / self.current_root.size) * 100.0
                    kind = "Folder / Group" if new_hover.is_dir else f"File ({new_hover.category})"
                    filter_tag = ""
                    if self.filter_query:
                        is_match = node_or_descendant_matches(new_hover, self.filter_query)
                        filter_tag = " • <span style='color:#00f5d4;'>[Matches Filter]</span>" if is_match else " • <span style='color:#8b949e;'>[Dimmed]</span>"
                    tip = (
                        f"<b>{bidi_isolate(new_hover.name)}</b>{filter_tag}<br/>"
                        f"Size: <b>{format_size(new_hover.size)}</b> ({pct:.2f}%)<br/>"
                        f"Type: {kind}<br/>"
                        f"Path: {bidi_isolate(new_hover.path)}<br/>"
                        f"<i>Drag mouse to select multiple • Double-click folder to zoom in • Right-click for actions</i>"
                    )
                    self.setToolTip(tip)
                else:
                    self.setToolTip("")
                self.update()

        def mouseReleaseEvent(self, event):
            if event.button() == Qt.MouseButton.LeftButton:
                if self.is_rubber_banding:
                    self.is_rubber_banding = False
                    self.nodes_selected.emit(self.selected_nodes)
                    self.update()
                else:
                    # Single click selection
                    r = self._rect_at(event.position())
                    if r:
                        self.selected_nodes = [r.node]
                        self.nodes_selected.emit(self.selected_nodes)
                    elif self.current_root:
                        self.selected_nodes = [self.current_root]
                        self.nodes_selected.emit(self.selected_nodes)
                    self.update()

        def leaveEvent(self, event):
            self.hovered_node = None
            self.update()

        def mouseDoubleClickEvent(self, event):
            if event.button() == Qt.MouseButton.LeftButton:
                r = self._rect_at(event.position())
                if r and r.node:
                    if r.node.is_dir and r.node.children:
                        self.node_zoomed.emit(r.node)
                    elif r.node.parent and r.node.parent is not self.current_root and r.node.parent.children:
                        self.node_zoomed.emit(r.node.parent)

        def paintEvent(self, event):
            painter = QPainter(self)
            painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
            painter.setRenderHint(QPainter.RenderHint.TextAntialiasing, True)

            painter.fillRect(self.rect(), QColor("#0d1017"))

            if not self.current_root or not self.rects:
                painter.setPen(QColor("#8b949e"))
                font = painter.font()
                font.setPointSize(12)
                painter.setFont(font)
                painter.drawText(
                    self.rect(),
                    Qt.AlignmentFlag.AlignCenter,
                    "Select a folder or drive above and click 'Scan' or 'Search as Admin' to render the Treemap.\n"
                    "Tip: You can drag with your mouse like on Windows to select multiple files at once!",
                )
                return

            has_active_filter = bool(self.filter_query)
            sel_set = set(self.selected_nodes)

            for r in self.rects:
                rx, ry, rw, rh = r.x, r.y, r.w, r.h
                if rw < 1.0 or rh < 1.0:
                    continue

                is_hovered = (r.node is self.hovered_node)
                is_selected = (r.node in sel_set)
                is_match = r.is_matching

                dim_factor = 1.0
                if has_active_filter and not is_match:
                    dim_factor = 0.28

                if r.is_group_header:
                    frame_rect = QRectF(rx + 0.5, ry + 0.5, rw - 1.0, rh - 1.0)
                    base_col = QColor(r.node.color if r.node.color != "#3b4252" else "#262c3a")
                    bg_col = base_col.darker(240)
                    if dim_factor < 1.0:
                        bg_col.setAlphaF(dim_factor)
                    painter.fillRect(frame_rect, bg_col)

                    header_h = min(20.0, rh)
                    header_rect = QRectF(rx + 0.5, ry + 0.5, rw - 1.0, header_h)
                    h_grad = QLinearGradient(header_rect.topLeft(), header_rect.bottomLeft())
                    h_c1 = base_col.lighter(115 if is_hovered else 100)
                    h_c2 = base_col.darker(135)
                    if dim_factor < 1.0:
                        h_c1.setAlphaF(dim_factor)
                        h_c2.setAlphaF(dim_factor)
                    h_grad.setColorAt(0.0, h_c1)
                    h_grad.setColorAt(1.0, h_c2)
                    painter.fillRect(header_rect, QBrush(h_grad))

                    if is_selected:
                        border_col = QColor("#00f5d4")
                        pen_w = 2.4
                    elif has_active_filter and is_match:
                        border_col = QColor("#ffbe0b")
                        pen_w = 2.0
                    elif is_hovered:
                        border_col = QColor("#ffffff")
                        pen_w = 1.8
                    else:
                        border_col = QColor("#30363d")
                        pen_w = 1.0
                    painter.setPen(QPen(border_col, pen_w))
                    painter.drawRect(frame_rect)

                    if rw >= 55 and header_h >= 13:
                        text_col = QColor("#f0f6fc")
                        if dim_factor < 1.0:
                            text_col.setAlphaF(0.4)
                        painter.setPen(text_col)
                        f = painter.font()
                        f.setBold(True)
                        f.setPointSize(9)
                        painter.setFont(f)
                        h_fm = QFontMetrics(f)
                        label_str = f"📁 {bidi_isolate(r.node.name)}  ({format_size(r.node.size)})"
                        elided = h_fm.elidedText(label_str, Qt.TextElideMode.ElideRight, int(rw - 10))
                        painter.drawText(
                            QRectF(rx + 5, ry + 1, rw - 10, header_h - 2),
                            Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft,
                            elided,
                        )
                else:
                    pad = 0.75 if (rw > 3 and rh > 3) else 0.0
                    block_rect = QRectF(rx + pad, ry + pad, max(0.5, rw - 2 * pad), max(0.5, rh - 2 * pad))

                    base_hex = r.node.color if not r.node.is_dir else "#3d5a80"
                    base_color = QColor(base_hex)
                    if is_hovered or is_selected:
                        base_color = base_color.lighter(125)

                    c_top = base_color.lighter(125)
                    c_mid = base_color
                    c_bot = base_color.darker(155)

                    if dim_factor < 1.0:
                        c_top = QColor(45, 52, 64)
                        c_mid = QColor(30, 36, 46)
                        c_bot = QColor(18, 22, 28)

                    grad = QLinearGradient(block_rect.topLeft(), block_rect.bottomRight())
                    grad.setColorAt(0.0, c_top)
                    grad.setColorAt(0.45, c_mid)
                    grad.setColorAt(1.0, c_bot)
                    painter.fillRect(block_rect, QBrush(grad))

                    if is_selected:
                        # Vivid Cyan/Blue border for selected items
                        painter.setPen(QPen(QColor("#00f5d4"), 2.4))
                        painter.drawRect(block_rect)
                    elif has_active_filter and is_match:
                        painter.setPen(QPen(QColor("#ffbe0b"), 1.8))
                        painter.drawRect(block_rect)
                    elif is_hovered:
                        painter.setPen(QPen(QColor("#ffffff"), 1.6))
                        painter.drawRect(block_rect)
                    elif rw >= 6 and rh >= 6:
                        p_col = QColor(10, 12, 18, 170) if dim_factor == 1.0 else QColor(10, 12, 18, 220)
                        painter.setPen(QPen(p_col, 0.8))
                        painter.drawRect(block_rect)

                    if rw >= 46 and rh >= 20:
                        f = painter.font()
                        f.setBold(is_selected or (has_active_filter and is_match))
                        f.setPointSize(8 if rh < 34 else 9)
                        painter.setFont(f)
                        b_fm = QFontMetrics(f)

                        name_isolated = bidi_isolate(r.node.name)
                        size_str = format_size(r.node.size)
                        text_rect = QRectF(block_rect.x() + 4, block_rect.y() + 2, block_rect.width() - 8, block_rect.height() - 4)

                        text_color = QColor("#ffffff")
                        if dim_factor < 1.0:
                            text_color = QColor("#5b6573")

                        painter.setPen(text_color)
                        if rh >= 36 and rw >= 65:
                            line1 = b_fm.elidedText(name_isolated, Qt.TextElideMode.ElideMiddle, int(text_rect.width()))
                            line2 = b_fm.elidedText(size_str, Qt.TextElideMode.ElideRight, int(text_rect.width()))
                            painter.drawText(
                                text_rect,
                                Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft,
                                f"{line1}\n{line2}",
                            )
                        else:
                            line1 = b_fm.elidedText(name_isolated, Qt.TextElideMode.ElideMiddle, int(text_rect.width()))
                            painter.drawText(
                                text_rect,
                                Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft,
                                line1,
                            )

            # Draw Windows-Style Translucent Blue Selection Box (Rubber-Band Marquee)
            if self.is_rubber_banding:
                sel_box = self._get_selection_box()
                # Windows Blue fill: rgba(0, 120, 215, 65)
                fill_color = QColor(0, 120, 215, 65)
                border_color = QColor(0, 120, 215, 230)
                painter.fillRect(sel_box, fill_color)
                painter.setPen(QPen(border_color, 1.5, Qt.PenStyle.SolidLine))
                painter.drawRect(sel_box)

    class WizTreeUbuntuMainWindow(QMainWindow):
        def __init__(self, start_path: Optional[str] = None):
            super().__init__()
            self.setWindowTitle("WizTree Ubuntu Edition — Visual Treemap Disk Space Analyzer")
            self.resize(1360, 840)

            self.raw_scan_root: Optional[ScanNode] = None
            self.display_root: Optional[ScanNode] = None
            self.active_filtered_root: Optional[ScanNode] = None
            self.zoom_stack: List[ScanNode] = []
            self.current_selected_nodes: List[ScanNode] = []
            self.scan_thread: Optional[ScanWorkerThread] = None
            self.target_scan_path: str = os.path.abspath(start_path or os.path.expanduser("~"))

            self._apply_dark_stylesheet()
            self._build_ui()

            if start_path:
                QTimer.singleShot(150, lambda: self.start_scan(as_admin=False))

        def _apply_dark_stylesheet(self):
            self.setStyleSheet(
                """
                QMainWindow, QWidget {
                    background-color: #11151c;
                    color: #e6edf3;
                    font-family: "Ubuntu", "Noto Sans", "Noto Sans Hebrew", "DejaVu Sans", sans-serif;
                    font-size: 10pt;
                }
                QFrame#CardFrame {
                    background-color: #161b22;
                    border: 1px solid #30363d;
                    border-radius: 8px;
                }
                QFrame#FilterFrame {
                    background-color: #161b22;
                    border: 1px solid #30363d;
                    border-bottom: 2px solid #0078d7;
                    border-radius: 6px;
                }
                QPushButton {
                    background-color: #21262d;
                    color: #e6edf3;
                    border: 1px solid #363b42;
                    border-radius: 6px;
                    padding: 6px 12px;
                    font-weight: 500;
                }
                QPushButton:hover {
                    background-color: #30363d;
                    border-color: #8b949e;
                }
                QPushButton#PrimaryBtn {
                    background-color: #238636;
                    border-color: #2ea043;
                    color: #ffffff;
                    font-weight: bold;
                }
                QPushButton#PrimaryBtn:hover {
                    background-color: #2ea043;
                }
                QPushButton#AdminBtn {
                    background-color: #9e6a03;
                    border-color: #d29922;
                    color: #ffffff;
                    font-weight: bold;
                }
                QPushButton#AdminBtn:hover {
                    background-color: #bb8009;
                }
                QPushButton#ShredBtn {
                    background-color: #da3633;
                    border-color: #f85149;
                    color: #ffffff;
                    font-weight: bold;
                }
                QPushButton#ShredBtn:hover {
                    background-color: #f85149;
                }
                QPushButton#ShortcutBtn {
                    background-color: #0078d7;
                    border-color: #2b88d8;
                    color: #ffffff;
                    font-weight: bold;
                }
                QPushButton#ShortcutBtn:hover {
                    background-color: #106ebe;
                }
                QLineEdit, QComboBox, QTextEdit, QTableWidget {
                    background-color: #0d1117;
                    color: #e6edf3;
                    border: 1px solid #30363d;
                    border-radius: 6px;
                    padding: 4px 8px;
                }
                QLineEdit:focus {
                    border: 1px solid #0078d7;
                }
                QHeaderView::section {
                    background-color: #161b22;
                    color: #8b949e;
                    border: none;
                    border-bottom: 1px solid #30363d;
                    padding: 5px;
                    font-weight: bold;
                }
                QProgressBar {
                    background-color: #0d1117;
                    border: 1px solid #30363d;
                    border-radius: 5px;
                    text-align: center;
                    color: #ffffff;
                    height: 18px;
                }
                QProgressBar::chunk {
                    background-color: #0078d7;
                    border-radius: 4px;
                }
                """
            )

        def _build_ui(self):
            central = QWidget()
            self.setCentralWidget(central)
            main_layout = QVBoxLayout(central)
            main_layout.setContentsMargins(10, 10, 10, 10)
            main_layout.setSpacing(8)

            # 1. Top Control Bar
            top_bar = QFrame()
            top_bar.setObjectName("CardFrame")
            top_layout = QHBoxLayout(top_bar)
            top_layout.setContentsMargins(10, 8, 10, 8)
            top_layout.setSpacing(8)

            lbl_target = QLabel("<b>Target:</b>")
            self.path_input = QLineEdit(self.target_scan_path)
            self.path_input.setMinimumWidth(220)

            btn_browse = QPushButton("Browse...")
            btn_browse.clicked.connect(self._on_browse)

            btn_scan = QPushButton("⚡ Scan Now")
            btn_scan.setObjectName("PrimaryBtn")
            btn_scan.clicked.connect(lambda: self.start_scan(as_admin=False))

            btn_admin_scan = QPushButton("🛡️ Search as Admin")
            btn_admin_scan.setObjectName("AdminBtn")
            btn_admin_scan.setToolTip(
                "Prompts for Administrator password (Polkit) and scans protected system folders (/root, /var, etc.)"
            )
            btn_admin_scan.clicked.connect(lambda: self.start_scan(as_admin=True))

            btn_desktop_icon = QPushButton("🎨 Add Icon to Desktop")
            btn_desktop_icon.setObjectName("ShortcutBtn")
            btn_desktop_icon.setToolTip(
                "Creates a trusted, clickable shortcut icon on your Ubuntu Desktop ('עמוד הבית / שולחן העבודה') with custom Treemap disk icon"
            )
            btn_desktop_icon.clicked.connect(self._action_create_desktop_shortcut)

            lbl_mode = QLabel("<b>Distribution:</b>")
            self.mode_combo = QComboBox()
            self.mode_combo.addItem("📁 By Folders (Hierarchy)", "folders")
            self.mode_combo.addItem("🎨 By File Types (Extensions)", "filetypes")
            self.mode_combo.currentIndexChanged.connect(self._on_distribution_mode_changed)

            self.chk_color_folders = QCheckBox("Color by Folder")
            self.chk_color_folders.setToolTip("When checked, colors blocks by parent folder instead of file extension")
            self.chk_color_folders.toggled.connect(self._on_color_mode_changed)

            self.chk_filter_virtual = QCheckBox("Skip Virtual Mounts")
            self.chk_filter_virtual.setChecked(True)
            self.chk_filter_virtual.setToolTip(
                "Automatically filters out virtual filesystems (/proc, /sys, /dev, /run, /snap) for accurate disk totals"
            )

            top_layout.addWidget(lbl_target)
            top_layout.addWidget(self.path_input, 1)
            top_layout.addWidget(btn_browse)
            top_layout.addWidget(btn_scan)
            top_layout.addWidget(btn_admin_scan)
            top_layout.addWidget(btn_desktop_icon)
            top_layout.addSpacing(6)
            top_layout.addWidget(lbl_mode)
            top_layout.addWidget(self.mode_combo)
            top_layout.addWidget(self.chk_color_folders)
            top_layout.addWidget(self.chk_filter_virtual)
            main_layout.addWidget(top_bar)

            # 2. Navigation Breadcrumb & Color Legend Bar
            nav_bar = QFrame()
            nav_bar.setObjectName("CardFrame")
            nav_layout = QHBoxLayout(nav_bar)
            nav_layout.setContentsMargins(10, 5, 10, 5)
            nav_layout.setSpacing(8)

            self.btn_zoom_root = QPushButton("🏠 Root")
            self.btn_zoom_root.setEnabled(False)
            self.btn_zoom_root.clicked.connect(self._zoom_to_root)

            self.btn_zoom_up = QPushButton("⬆️ Up One Level")
            self.btn_zoom_up.setEnabled(False)
            self.btn_zoom_up.clicked.connect(self._zoom_up)

            self.lbl_breadcrumb = QLabel("<b>Current View:</b> Not scanned yet")
            self.lbl_breadcrumb.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)

            nav_layout.addWidget(self.btn_zoom_root)
            nav_layout.addWidget(self.btn_zoom_up)
            nav_layout.addWidget(self.lbl_breadcrumb, 1)

            for cat_key, (_cat_title, hex_col, _exts) in FILE_CATEGORIES.items():
                badge = QLabel(f"<span style='color:{hex_col};'>■</span> {cat_key.split()[0]}")
                badge.setStyleSheet("font-size: 9pt; padding-left: 4px;")
                nav_layout.addWidget(badge)

            main_layout.addWidget(nav_bar)

            # 3. Main Workspace Splitter: Treemap + Search Bar (Left ~70%) vs Inspector (Right ~30%)
            splitter = QSplitter(Qt.Orientation.Horizontal)

            # Left Container: Search Bar + Treemap Canvas
            left_container = QWidget()
            left_vbox = QVBoxLayout(left_container)
            left_vbox.setContentsMargins(0, 0, 0, 0)
            left_vbox.setSpacing(6)

            # Live Search & Filter Bar
            filter_bar = QFrame()
            filter_bar.setObjectName("FilterFrame")
            f_layout = QHBoxLayout(filter_bar)
            f_layout.setContentsMargins(10, 6, 10, 6)
            f_layout.setSpacing(8)

            lbl_filter_icon = QLabel("<b>🔍 Search:</b>")
            lbl_filter_icon.setStyleSheet("color: #00f5d4;")

            self.filter_input = QLineEdit()
            self.filter_input.setPlaceholderText("Filter by name, extension (*.iso, *.mp4), or Hebrew keyword...")
            self.filter_input.setClearButtonEnabled(True)
            self.filter_input.textChanged.connect(self._on_filter_changed)

            self.filter_mode_combo = QComboBox()
            self.filter_mode_combo.addItem("✨ Highlight Matches on Map", "highlight")
            self.filter_mode_combo.addItem("🎯 Show Only Matching Files", "isolate")
            self.filter_mode_combo.currentIndexChanged.connect(self._on_filter_changed)

            self.lbl_filter_stats = QLabel("Tip: Click & drag mouse on map to select multiple files!")
            self.lbl_filter_stats.setStyleSheet("color: #8b949e; font-size: 9pt; min-width: 170px;")

            btn_clear_filter = QPushButton("✕ Clear")
            btn_clear_filter.clicked.connect(lambda: self.filter_input.clear())

            f_layout.addWidget(lbl_filter_icon)
            f_layout.addWidget(self.filter_input, 1)
            f_layout.addWidget(self.filter_mode_combo)
            f_layout.addWidget(self.lbl_filter_stats)
            f_layout.addWidget(btn_clear_filter)
            left_vbox.addWidget(filter_bar)

            # Treemap Frame
            treemap_frame = QFrame()
            treemap_frame.setObjectName("CardFrame")
            tm_layout = QVBoxLayout(treemap_frame)
            tm_layout.setContentsMargins(4, 4, 4, 4)
            self.treemap = TreemapCanvas()
            self.treemap.nodes_selected.connect(self._on_nodes_selected)
            self.treemap.node_zoomed.connect(self._on_node_zoomed)
            self.treemap.context_action_requested.connect(self._show_context_menu)
            tm_layout.addWidget(self.treemap)
            left_vbox.addWidget(treemap_frame, 1)

            splitter.addWidget(left_container)

            # Right Container: In-Window File Inspector & Live Preview Panel
            inspector_frame = QFrame()
            inspector_frame.setObjectName("CardFrame")
            inspector_frame.setMinimumWidth(360)
            insp_layout = QVBoxLayout(inspector_frame)
            insp_layout.setContentsMargins(12, 12, 12, 12)
            insp_layout.setSpacing(8)

            insp_header = QLabel("<b>🔍 File Inspector & Multi-Selection Panel</b>")
            insp_header.setStyleSheet("font-size: 11pt; color: #58a6ff;")
            insp_layout.addWidget(insp_header)

            self.lbl_sel_name = QLabel("Select any block on the Treemap or drag with mouse")
            self.lbl_sel_name.setWordWrap(True)
            self.lbl_sel_name.setStyleSheet("font-size: 11pt; font-weight: bold; color: #ffffff;")
            self.lbl_sel_name.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            insp_layout.addWidget(self.lbl_sel_name)

            self.lbl_sel_meta = QLabel("")
            self.lbl_sel_meta.setWordWrap(True)
            self.lbl_sel_meta.setStyleSheet("color: #8b949e; font-size: 9.5pt;")
            self.lbl_sel_meta.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            insp_layout.addWidget(self.lbl_sel_meta)

            act_row1 = QHBoxLayout()
            self.btn_open_item = QPushButton("📂 Open Item")
            self.btn_open_item.clicked.connect(self._action_open_selected)
            self.btn_reveal_item = QPushButton("🧭 Reveal in Files")
            self.btn_reveal_item.clicked.connect(self._action_reveal_selected)
            act_row1.addWidget(self.btn_open_item)
            act_row1.addWidget(self.btn_reveal_item)
            insp_layout.addLayout(act_row1)

            act_row2 = QHBoxLayout()
            self.btn_shred_gui = QPushButton("🔥 Send to Shredder")
            self.btn_shred_gui.setObjectName("ShredBtn")
            self.btn_shred_gui.setToolTip(
                "Opens ~/.local/bin/file_shredder_gui.py pre-linked to selected path(s)"
            )
            self.btn_shred_gui.clicked.connect(self._action_send_to_shredder)

            self.btn_quick_shred = QPushButton("⚡ Shred (3-Pass)")
            self.btn_quick_shred.setToolTip("Immediately overwrites and deletes the selected item(s) after confirmation")
            self.btn_quick_shred.clicked.connect(self._action_quick_shred)
            act_row2.addWidget(self.btn_shred_gui)
            act_row2.addWidget(self.btn_quick_shred)
            insp_layout.addLayout(act_row2)

            lbl_prev_title = QLabel("<b>Live File Preview / Multi-Item Summary:</b>")
            insp_layout.addWidget(lbl_prev_title)

            self.preview_stack = QStackedWidget()
            self.preview_stack.setFixedHeight(185)

            self.text_preview = QTextEdit()
            self.text_preview.setReadOnly(True)
            self.text_preview.setPlaceholderText("Click or drag-select files on the Treemap to preview them here...")
            self.preview_stack.addWidget(self.text_preview)

            self.image_preview_lbl = QLabel()
            self.image_preview_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self.image_preview_lbl.setStyleSheet("background-color: #0d1117; border: 1px solid #30363d; border-radius: 6px;")
            self.preview_stack.addWidget(self.image_preview_lbl)

            insp_layout.addWidget(self.preview_stack)

            self.lbl_table_title = QLabel("<b>Largest Items in Scope:</b>")
            insp_layout.addWidget(self.lbl_table_title)

            self.items_table = QTableWidget(0, 3)
            self.items_table.setHorizontalHeaderLabels(["Name", "Size", "%"])
            self.items_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
            self.items_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
            self.items_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
            self.items_table.verticalHeader().setVisible(False)
            self.items_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
            self.items_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
            self.items_table.cellClicked.connect(self._on_table_row_clicked)
            self.items_table.cellDoubleClicked.connect(self._on_table_row_double_clicked)
            insp_layout.addWidget(self.items_table, 1)

            splitter.addWidget(inspector_frame)
            splitter.setStretchFactor(0, 7)
            splitter.setStretchFactor(1, 3)
            main_layout.addWidget(splitter, 1)

            # 4. Bottom Status & Progress Bar
            status_bar = QFrame()
            status_bar.setObjectName("CardFrame")
            status_layout = QHBoxLayout(status_bar)
            status_layout.setContentsMargins(10, 4, 10, 4)

            self.lbl_status = QLabel("Ready. Drag mouse on the Treemap for Windows-style blue multi-selection.")
            self.progress_bar = QProgressBar()
            self.progress_bar.setFixedWidth(220)
            self.progress_bar.setVisible(False)

            status_layout.addWidget(self.lbl_status, 1)
            status_layout.addWidget(self.progress_bar)
            main_layout.addWidget(status_bar)

            self._table_nodes: List[ScanNode] = []

        # ----------------------------------------------------------------------
        # Desktop Shortcut Action
        # ----------------------------------------------------------------------

        def _action_create_desktop_shortcut(self):
            ok, msg = create_desktop_shortcut()
            if ok:
                QMessageBox.information(
                    self,
                    "Desktop Shortcut & Icon Created",
                    f"Successfully created desktop shortcut with custom icon!\n\n"
                    f"A beautiful 'WizTree Ubuntu' icon is now on your Desktop ("
                    f"עמוד הבית / שולחן העבודה) and in your Applications menu.\n\n"
                    f"Double-click it anytime to launch directly.",
                )
                self.lbl_status.setText("Desktop shortcut and custom icon created successfully.")
            else:
                QMessageBox.warning(self, "Shortcut Creation Failed", msg)

        # ----------------------------------------------------------------------
        # Scanning & Mode Switching
        # ----------------------------------------------------------------------

        def _on_browse(self):
            chosen = QFileDialog.getExistingDirectory(
                self,
                "Select Folder or Drive to Analyze",
                self.path_input.text().strip() or os.path.expanduser("~"),
            )
            if chosen:
                self.path_input.setText(chosen)
                self.start_scan(as_admin=False)

        def start_scan(self, as_admin: bool = False):
            target = self.path_input.text().strip()
            if not target or not os.path.exists(target):
                QMessageBox.warning(self, "Invalid Path", f"The path does not exist:\n{target}")
                return

            if self.scan_thread and self.scan_thread.isRunning():
                self.scan_thread.cancel()
                self.scan_thread.wait(500)

            self.target_scan_path = os.path.abspath(target)
            self.progress_bar.setVisible(True)
            self.progress_bar.setRange(0, 0)
            mode_str = "Administrator (Polkit)" if as_admin else "Standard User"
            self.lbl_status.setText(f"Scanning {bidi_isolate(self.target_scan_path)} ({mode_str})...")

            self.scan_thread = ScanWorkerThread(
                target_path=self.target_scan_path,
                filter_virtual=self.chk_filter_virtual.isChecked(),
                as_admin=as_admin,
            )
            self.scan_thread.progress.connect(self._on_scan_progress)
            self.scan_thread.finished_scan.connect(self._on_scan_finished)
            self.scan_thread.failed_scan.connect(self._on_scan_failed)
            self.scan_thread.start()

        def _on_scan_progress(self, files: int, num_bytes: int, current_path: str):
            self.lbl_status.setText(
                f"Scanning: {files:,} files ({format_size(num_bytes)}) — {bidi_isolate(current_path)}"
            )

        def _on_scan_finished(self, tree: ScanNode, files: int, dirs: int, perm_errors: int, was_admin: bool):
            self.progress_bar.setVisible(False)
            self.raw_scan_root = tree
            self.zoom_stack.clear()
            self._rebuild_display_root()

            badge = "🛡️ Admin Scan" if was_admin else "User Scan"
            perm_note = f" • {perm_errors} locked items skipped (use 'Search as Admin' to include)" if (perm_errors and not was_admin) else ""
            self.lbl_status.setText(
                f"{badge} Complete: {format_size(tree.size)} across {files:,} files and {dirs:,} folders{perm_note}"
            )

        def _on_scan_failed(self, err_msg: str):
            self.progress_bar.setVisible(False)
            self.lbl_status.setText(f"Scan stopped: {err_msg}")

        def _rebuild_display_root(self):
            if not self.raw_scan_root:
                return
            mode = self.mode_combo.currentData()
            if mode == "filetypes":
                self.display_root = build_filetype_grouped_root(self.raw_scan_root)
            else:
                self.display_root = self.raw_scan_root

            self.zoom_stack = [self.display_root]
            self._apply_current_zoom_view()

        def _on_distribution_mode_changed(self):
            if self.raw_scan_root:
                self._rebuild_display_root()

        def _on_color_mode_changed(self):
            if self.zoom_stack:
                self.treemap.set_root_node(
                    self.zoom_stack[-1],
                    color_by_folder=self.chk_color_folders.isChecked(),
                    filter_query=self.filter_input.text().strip(),
                )

        def _on_filter_changed(self):
            query = self.filter_input.text().strip()
            mode = self.filter_mode_combo.currentData()

            if not self.zoom_stack:
                self.lbl_filter_stats.setText("No scan active")
                return

            current_base = self.zoom_stack[-1]

            if not query:
                self.lbl_filter_stats.setText("Tip: Drag mouse for blue multi-selection")
                self.treemap.set_root_node(
                    current_base,
                    color_by_folder=self.chk_color_folders.isChecked(),
                    filter_query="",
                )
                self._update_inspector_table(self.current_selected_nodes or [current_base], current_base)
                return

            _, count, num_bytes = build_filtered_isolated_tree(current_base, query)
            pct = (num_bytes / current_base.size * 100.0) if current_base.size > 0 else 0.0
            self.lbl_filter_stats.setText(f"Matched: {count:,} items ({format_size(num_bytes)} • {pct:.1f}%)")

            if mode == "isolate":
                filtered_tree, _, _ = build_filtered_isolated_tree(current_base, query)
                display_node = filtered_tree or ScanNode(name="No matching files", path="", size=0, is_dir=True)
                self.treemap.set_root_node(
                    display_node,
                    color_by_folder=self.chk_color_folders.isChecked(),
                    filter_query="",
                )
                self._update_inspector_table([display_node], display_node)
            else:
                self.treemap.set_root_node(
                    current_base,
                    color_by_folder=self.chk_color_folders.isChecked(),
                    filter_query=query,
                )
                self._update_inspector_table(self.current_selected_nodes or [current_base], current_base)

        def _apply_current_zoom_view(self):
            if not self.zoom_stack:
                return
            cur = self.zoom_stack[-1]
            self.btn_zoom_root.setEnabled(len(self.zoom_stack) > 1)
            self.btn_zoom_up.setEnabled(len(self.zoom_stack) > 1)

            crumbs = "  ▸  ".join(bidi_isolate(n.name) for n in self.zoom_stack)
            self.lbl_breadcrumb.setText(
                f"<b>View:</b> {crumbs}   <span style='color:#58a6ff;'>({format_size(cur.size)})</span>"
            )
            self._on_filter_changed()
            self._on_nodes_selected([cur])

        def _on_node_zoomed(self, node: ScanNode):
            if node and node.is_dir and node.children:
                if not self.zoom_stack or self.zoom_stack[-1] is not node:
                    self.zoom_stack.append(node)
                    self._apply_current_zoom_view()

        def _zoom_to_root(self):
            if len(self.zoom_stack) > 1:
                self.zoom_stack = [self.zoom_stack[0]]
                self._apply_current_zoom_view()

        def _zoom_up(self):
            if len(self.zoom_stack) > 1:
                self.zoom_stack.pop()
                self._apply_current_zoom_view()

        # ----------------------------------------------------------------------
        # Multi-Selection & In-Window Inspector Handling
        # ----------------------------------------------------------------------

        def _on_nodes_selected(self, nodes: List[ScanNode]):
            self.current_selected_nodes = [n for n in nodes if n]
            if not self.current_selected_nodes:
                if self.zoom_stack:
                    self.current_selected_nodes = [self.zoom_stack[-1]]
                else:
                    return

            view_root = self.zoom_stack[-1] if self.zoom_stack else self.current_selected_nodes[0]
            count = len(self.current_selected_nodes)

            if count == 1:
                node = self.current_selected_nodes[0]
                pct = (node.size / view_root.size * 100.0) if (view_root and view_root.size > 0) else 100.0
                icon = "📁" if node.is_dir else "📄"
                self.lbl_sel_name.setText(f"{icon}  {bidi_isolate(node.name)}")

                mtime_str = (
                    datetime.datetime.fromtimestamp(node.mtime).strftime("%Y-%m-%d %H:%M:%S")
                    if node.mtime > 0 else "N/A"
                )
                perms_str = "N/A"
                owner_str = "User"
                try:
                    if os.path.exists(node.path):
                        st = os.stat(node.path, follow_symlinks=False)
                        perms_str = stat.filemode(st.st_mode)
                        owner_str = "root (Admin)" if st.st_uid == 0 else f"UID {st.st_uid}"
                except Exception:
                    pass

                self.lbl_sel_meta.setText(
                    f"<b>Size:</b> {format_size(node.size)} ({node.size:,} bytes • {pct:.2f}% of view)<br/>"
                    f"<b>Path:</b> {bidi_isolate(node.path)}<br/>"
                    f"<b>Category:</b> {node.category} &nbsp;|&nbsp; <b>Modified:</b> {mtime_str}<br/>"
                    f"<b>Permissions:</b> <code>{perms_str}</code> &nbsp;|&nbsp; <b>Owner:</b> {owner_str}"
                )
                self.btn_open_item.setText("📂 Open Item")
                self.btn_reveal_item.setText("🧭 Reveal in Files")
                self.btn_shred_gui.setText("🔥 Send to Shredder")
                self.btn_quick_shred.setText("⚡ Shred (3-Pass)")
                self._update_live_preview(node)

            else:
                # Multi-Selection Summary
                total_size = sum(n.size for n in self.current_selected_nodes)
                pct = (total_size / view_root.size * 100.0) if (view_root and view_root.size > 0) else 100.0
                num_files = sum(1 for n in self.current_selected_nodes if not n.is_dir)
                num_dirs = sum(1 for n in self.current_selected_nodes if n.is_dir)

                self.lbl_sel_name.setText(f"📦 Blue Box Selection ({count:,} items selected)")
                self.lbl_sel_meta.setText(
                    f"<b>Combined Size:</b> {format_size(total_size)} ({total_size:,} bytes • {pct:.2f}% of view)<br/>"
                    f"<b>Contents:</b> {num_files:,} files and {num_dirs:,} folders selected<br/>"
                    f"<i>Drag another rectangle on the Treemap or click on any single item to clear.</i>"
                )
                self.btn_open_item.setText(f"📂 Open All ({count})")
                self.btn_reveal_item.setText("🧭 Reveal First in Files")
                self.btn_shred_gui.setText(f"🔥 Send All ({count}) to Shredder")
                self.btn_quick_shred.setText(f"⚡ Batch Shred ({count} items)")

                # Multi-selection summary in preview area
                self.preview_stack.setCurrentIndex(0)
                summary_lines = [
                    f"=== Selected Items ({count:,}) ===",
                    f"Total Combined Size: {format_size(total_size)}",
                    f"Files: {num_files:,} | Folders: {num_dirs:,}",
                    "",
                    "Selected items list:",
                ]
                for n in self.current_selected_nodes[:40]:
                    p = "📁" if n.is_dir else "📄"
                    summary_lines.append(f" {p} {bidi_isolate(n.name)}  ({format_size(n.size)})")
                if count > 40:
                    summary_lines.append(f" ... and {count - 40} more items.")
                self.text_preview.setPlainText("\n".join(summary_lines))

            self._update_inspector_table(self.current_selected_nodes, view_root)

        def _update_live_preview(self, node: ScanNode):
            if node.is_dir:
                self.preview_stack.setCurrentIndex(0)
                summary_lines = [
                    f"Folder / Group: {bidi_isolate(node.name)}",
                    f"Total Size:     {format_size(node.size)}",
                    f"Files Inside:   {node.file_count:,}",
                    f"Subfolders:     {node.dir_count:,}",
                    "",
                    "Tip: Double-click this block on the Treemap to zoom inside it,",
                    "or drag the mouse to select multiple files at once.",
                ]
                self.text_preview.setPlainText("\n".join(summary_lines))
                return

            fp = node.path
            if not os.path.isfile(fp):
                self.preview_stack.setCurrentIndex(0)
                self.text_preview.setPlainText("Group summary item.")
                return

            ext = node.ext.lower()
            image_exts = {".png", ".jpg", ".jpeg", ".webp", ".bmp", ".gif", ".svg", ".ico"}
            if ext in image_exts:
                pix = QPixmap(fp)
                if not pix.isNull():
                    self.preview_stack.setCurrentIndex(1)
                    scaled = pix.scaled(
                        QSize(320, 175),
                        Qt.AspectRatioMode.KeepAspectRatio,
                        Qt.TransformationMode.SmoothTransformation,
                    )
                    self.image_preview_lbl.setPixmap(scaled)
                    return

            self.preview_stack.setCurrentIndex(0)
            try:
                with open(fp, "rb") as f:
                    sample = f.read(8192)
                if b"\x00" in sample[:512]:
                    hex_head = " ".join(f"{b:02X}" for b in sample[:96])
                    self.text_preview.setPlainText(
                        f"[Binary File — {node.category} ({ext})]\n\n"
                        f"First bytes (Hex):\n{hex_head}"
                    )
                else:
                    text_content = sample.decode("utf-8", errors="replace")
                    self.text_preview.setPlainText(text_content)
            except PermissionError:
                self.text_preview.setPlainText(
                    "🔒 Permission Denied to preview file contents.\n"
                    "Click 'Open as Admin' in the right-click menu or use 'Search as Admin'."
                )
            except Exception as e:
                self.text_preview.setPlainText(f"Cannot preview file: {e}")

        def _update_inspector_table(self, nodes: List[ScanNode], view_root: ScanNode):
            if not nodes:
                return

            if len(nodes) > 1:
                # In multi-selection mode, show the selected nodes in the table
                self.lbl_table_title.setText(f"<b>Selected Items ({len(nodes):,} items):</b>")
                children = sorted(nodes, key=lambda c: c.size, reverse=True)[:60]
                denom = sum(n.size for n in nodes) or 1
            else:
                node = nodes[0]
                scope_node = node if (node.is_dir and node.children) else view_root
                if not scope_node:
                    return
                q = self.filter_input.text().strip()
                raw_children = scope_node.children
                if q and self.filter_mode_combo.currentData() == "highlight":
                    matching_first = sorted(
                        raw_children,
                        key=lambda c: (1 if node_or_descendant_matches(c, q) else 0, c.size),
                        reverse=True,
                    )
                    children = matching_first[:60]
                else:
                    children = raw_children[:60]
                self.lbl_table_title.setText(f"<b>Largest Items in {bidi_isolate(scope_node.name)}:</b>")
                denom = scope_node.size if scope_node.size > 0 else 1

            self._table_nodes = children
            self.items_table.setRowCount(len(children))

            q = self.filter_input.text().strip()
            for row_idx, ch in enumerate(children):
                prefix = "📁 " if ch.is_dir else "📄 "
                is_match = node_or_descendant_matches(ch, q) if q else True
                name_str = f"{prefix}{bidi_isolate(ch.name)}"
                if q and is_match:
                    name_str = f"⭐ {name_str}"

                item_name = QTableWidgetItem(name_str)
                item_size = QTableWidgetItem(format_size(ch.size))
                item_size.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
                pct_val = (ch.size / denom) * 100.0
                item_pct = QTableWidgetItem(f"{pct_val:.1f}%")
                item_pct.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)

                self.items_table.setItem(row_idx, 0, item_name)
                self.items_table.setItem(row_idx, 1, item_size)
                self.items_table.setItem(row_idx, 2, item_pct)

        def _on_table_row_clicked(self, row: int, _col: int):
            if 0 <= row < len(self._table_nodes):
                target = self._table_nodes[row]
                self.current_selected_nodes = [target]
                self.treemap.set_selected_nodes(self.current_selected_nodes)
                self._on_nodes_selected(self.current_selected_nodes)

        def _on_table_row_double_clicked(self, row: int, _col: int):
            if 0 <= row < len(self._table_nodes):
                target = self._table_nodes[row]
                if target.is_dir and target.children:
                    self._on_node_zoomed(target)
                else:
                    self._action_open_selected()

        # ----------------------------------------------------------------------
        # Context Menu & Actions (Single & Batch)
        # ----------------------------------------------------------------------

        def _show_context_menu(self, nodes: List[ScanNode], global_pos: QPointF):
            if not nodes:
                return
            menu = QMenu(self)

            if len(nodes) == 1:
                node = nodes[0]
                if node.is_dir and node.children:
                    act_zoom = QAction("🔍 Zoom Into This Folder / Group", self)
                    act_zoom.triggered.connect(lambda: self._on_node_zoomed(node))
                    menu.addAction(act_zoom)
                    menu.addSeparator()

                act_open = QAction("📂 Open File / Folder", self)
                act_open.triggered.connect(self._action_open_selected)
                menu.addAction(act_open)

                act_reveal = QAction("🧭 Reveal in Ubuntu Files (Nautilus)", self)
                act_reveal.triggered.connect(self._action_reveal_selected)
                menu.addAction(act_reveal)

                act_admin = QAction("🛡️ Open as Administrator (Polkit)", self)
                act_admin.triggered.connect(self._action_open_as_admin)
                menu.addAction(act_admin)

                act_copy = QAction("📋 Copy Full Path", self)
                act_copy.triggered.connect(lambda: QApplication.clipboard().setText(node.path))
                menu.addAction(act_copy)

                menu.addSeparator()

                act_shred_gui = QAction("🔥 Send Path to File Shredder GUI", self)
                act_shred_gui.triggered.connect(self._action_send_to_shredder)
                menu.addAction(act_shred_gui)

                act_quick_shred = QAction("⚡ Quick Shred & Overwrite Now (3-Pass)...", self)
                act_quick_shred.triggered.connect(self._action_quick_shred)
                menu.addAction(act_quick_shred)

            else:
                # Batch Multi-Selection Menu
                header_act = QAction(f"📦 Selected: {len(nodes):,} items ({format_size(sum(n.size for n in nodes))})", self)
                header_act.setEnabled(False)
                menu.addAction(header_act)
                menu.addSeparator()

                act_open_all = QAction(f"📂 Open All Selected Items ({len(nodes)})", self)
                act_open_all.triggered.connect(self._action_open_selected)
                menu.addAction(act_open_all)

                act_copy_all = QAction(f"📋 Copy All Paths to Clipboard ({len(nodes)} paths)", self)
                act_copy_all.triggered.connect(
                    lambda: QApplication.clipboard().setText("\n".join(n.path for n in nodes))
                )
                menu.addAction(act_copy_all)

                menu.addSeparator()

                act_shred_gui = QAction(f"🔥 Send First Item to File Shredder GUI", self)
                act_shred_gui.triggered.connect(self._action_send_to_shredder)
                menu.addAction(act_shred_gui)

                act_quick_shred = QAction(f"⚡ Batch Shred & Overwrite All Selected ({len(nodes)} items)...", self)
                act_quick_shred.triggered.connect(self._action_quick_shred)
                menu.addAction(act_quick_shred)

            menu.exec(QCursor.pos())

        def _action_open_selected(self):
            for node in self.current_selected_nodes[:15]:
                if os.path.exists(node.path):
                    subprocess.Popen(["xdg-open", node.path])

        def _action_reveal_selected(self):
            if not self.current_selected_nodes:
                return
            node = self.current_selected_nodes[0]
            if not os.path.exists(node.path):
                return
            if os.path.isfile(node.path):
                subprocess.Popen(["nautilus", "--select", node.path])
            else:
                subprocess.Popen(["nautilus", node.path])

        def _action_open_as_admin(self):
            if not self.current_selected_nodes:
                return
            node = self.current_selected_nodes[0]
            admin_uri = f"admin://{os.path.abspath(node.path)}"
            if os.path.isdir(node.path):
                subprocess.Popen(["nautilus", admin_uri])
            else:
                editors = ["gnome-text-editor", "gedit", "xed"]
                ed = next((e for e in editors if shutil.which(e)), None)
                if ed:
                    subprocess.Popen([ed, admin_uri])
                else:
                    subprocess.Popen(["nautilus", f"admin://{os.path.dirname(os.path.abspath(node.path))}"])

        def _action_send_to_shredder(self):
            if not self.current_selected_nodes:
                return
            paths = [n.path for n in self.current_selected_nodes]
            QApplication.clipboard().setText("\n".join(paths))
            primary_path = paths[0]
            ok, msg = launch_external_file_shredder(primary_path)
            if ok:
                count_str = f"({len(paths)} paths copied to clipboard)" if len(paths) > 1 else ""
                self.lbl_status.setText(f"Sent to File Shredder {count_str}: {bidi_isolate(primary_path)}")
            else:
                QMessageBox.information(self, "File Shredder Integration", msg)

        def _action_quick_shred(self):
            if not self.current_selected_nodes:
                return
            nodes = self.current_selected_nodes
            count = len(nodes)
            total_size = sum(n.size for n in nodes)

            if count == 1:
                item_desc = f"{bidi_isolate(nodes[0].name)}\nPath: {bidi_isolate(nodes[0].path)}"
            else:
                item_desc = f"{count:,} selected items (Total: {format_size(total_size)})\nFirst item: {bidi_isolate(nodes[0].path)}"

            reply = QMessageBox.warning(
                self,
                f"Confirm Permanent 3-Pass Shred ({count} items)",
                f"Are you sure you want to permanently overwrite (3 passes) and shred:\n\n"
                f"{item_desc}\n\n"
                f"Combined Size: {format_size(total_size)}\n\n"
                f"This action CANNOT be undone!",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
                QMessageBox.StandardButton.Cancel,
            )
            if reply == QMessageBox.StandardButton.Yes:
                paths = [n.path for n in nodes]
                ok, msg = builtin_secure_shred(paths, passes=3)
                if ok:
                    self.lbl_status.setText(f"Shredded {count} item(s) — Refreshing view...")
                    self.start_scan(as_admin=False)
                else:
                    QMessageBox.critical(self, "Shred Failed", msg)

    app = QApplication(sys.argv)
    app.setApplicationName("WizTree Ubuntu Edition")

    # Set application icon in window title bar and dock
    custom_icon_path = install_custom_icons()
    if os.path.exists(custom_icon_path):
        app.setWindowIcon(QIcon(custom_icon_path))

    win = WizTreeUbuntuMainWindow(start_path=initial_path)
    win.show()
    sys.exit(app.exec())


# ==============================================================================
# One-Command Installer (--install)
# ==============================================================================

def install_wiztree_ubuntu():
    print("=== Installing WizTree Ubuntu Edition ===")
    res = subprocess.run(["dpkg", "-s", "python3-pyqt6"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if res.returncode != 0:
        print("[*] Installing PyQt6 graphical framework (python3-pyqt6)...")
        subprocess.run(["sudo", "apt-get", "update"])
        subprocess.run(["sudo", "apt-get", "install", "-y", "python3-pyqt6"])

    bin_dir = os.path.expanduser("~/.local/bin")
    os.makedirs(bin_dir, exist_ok=True)
    target_script = os.path.join(bin_dir, "wiztree_ubuntu.py")
    shutil.copy2(os.path.abspath(__file__), target_script)
    os.chmod(target_script, 0o755)
    print(f"[+] Installed executable to: {target_script}")

    # Generate custom Treemap disk icon and clickable desktop shortcut
    ok, msg = create_desktop_shortcut()
    if ok:
        print(f"[+] {msg}")
    else:
        print(f"[!] Warning: {msg}")

    print("\n[V] Installation complete! You can launch it by double-clicking the custom Desktop icon or running:")
    print(f"    python3 {target_script}")


if __name__ == "__main__":
    if len(sys.argv) >= 2 and sys.argv[1] == "--install":
        install_wiztree_ubuntu()
    elif len(sys.argv) >= 2 and sys.argv[1] == "--create-shortcut":
        ok, msg = create_desktop_shortcut()
        print(msg)
    elif len(sys.argv) >= 3 and sys.argv[1] == "--admin-scan-worker":
        target = sys.argv[2]
        fv = (sys.argv[3] == "1") if len(sys.argv) >= 4 else True
        sys.exit(run_admin_scan_worker(target, fv))
    else:
        initial = sys.argv[1] if len(sys.argv) >= 2 and os.path.exists(sys.argv[1]) else None
        run_gui(initial_path=initial)