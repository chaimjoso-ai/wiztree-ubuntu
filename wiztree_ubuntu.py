#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WizTree Ubuntu Edition — High-Speed Visual Disk Space Analyzer (Treemap)
========================================================================
Fixed & Optimized:
- 100% Vibrant Color Restoration: Every folder, file category, and extension
  group has distinct, vivid 3D cushioned colors (no more dull gray blocks!).
- Rock-Solid "Search as Admin" (pkexec): High-capacity file-based IPC + recursion
  safety prevents buffer deadlocks and sudden crashes on large / deep filesystems.
- Responsive Compact Layout: Two clean toolbars + scrollable inspector panel
  comfortably fits any screen resolution (from 1366x768 laptops up to 4K).
- Windows-Style Blue Rubber-Band Selection (Marquee drag multi-selection).
- Native Hebrew & English BiDi Isolation for clean rendering without scrambling.
- Custom High-Res 3D App Icon & Desktop Shortcut creator.
"""

import sys
import os

# Ensure deep filesystem traversal never hits Python recursion limits
sys.setrecursionlimit(50000)

import base64
import datetime
import fnmatch
import gzip
import json
import math
import shutil
import stat
import subprocess
import tempfile
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
# Vibrant Palette Definitions (WizTree High-Contrast Rich Mosaic Colors)
# ==============================================================================

VIBRANT_FOLDER_PALETTE = [
    "#3a86ff", "#e63946", "#06d6a0", "#f4a261", "#8338ec",
    "#ff006e", "#00bbf9", "#ffbe0b", "#9b5de5", "#2a9d8f",
    "#e76f51", "#43aa8b", "#f72585", "#4cc9f0", "#7209b7",
    "#38b000", "#fb5607", "#5e60ce", "#f9844a", "#118ab2",
    "#d90429", "#00f5d4", "#70e000", "#ff70a6"
]

FILE_CATEGORIES: Dict[str, Tuple[str, str, set]] = {
    "Video": (
        "Video & Movies",
        "#e63946",  # Vibrant Coral/Red
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
        "#00bbf9",  # Electric Cyan
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
        "#ff006e",  # Vivid Magenta / Pink
        {".so", ".a", ".o", ".ko", ".bin", ".run", ".exe", ".dll", ".log", ".bak", ".tmp", ".cache", ".swp"},
    ),
}

DEFAULT_CATEGORY_COLOR = "#4ea8de"

EXT_TO_CATEGORY: Dict[str, Tuple[str, str]] = {}
for cat_key, (_label, hex_color, ext_set) in FILE_CATEGORIES.items():
    for ext in ext_set:
        EXT_TO_CATEGORY[ext] = (cat_key, hex_color)


def classify_extension(filename: str) -> Tuple[str, str, str]:
    lower = filename.lower()
    _, ext = os.path.splitext(lower)
    if not ext or ext == ".":
        return ("[No Ext]", "Other Files", "#8338ec")
    cat_info = EXT_TO_CATEGORY.get(ext)
    if cat_info:
        return (ext, cat_info[0], cat_info[1])
    color = VIBRANT_FOLDER_PALETTE[abs(hash(ext)) % len(VIBRANT_FOLDER_PALETTE)]
    return (ext, "Other Files", color)


def get_node_color(node: "ScanNode", index: int = 0) -> str:
    """Returns the vibrant display color for any node (file, folder, or extension group)."""
    if node.color and node.color not in ("#3b4252", "#3d5a80", ""):
        return node.color
    # Deterministic palette assignment for folders based on their name hash
    return VIBRANT_FOLDER_PALETTE[abs(hash(node.name)) % len(VIBRANT_FOLDER_PALETTE)]


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

@dataclass(eq=False)
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
    color: str = ""
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
                "col": "#6c757d",
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
            "col": self.color,
        }

    @staticmethod
    def from_dict(data: dict, parent: Optional["ScanNode"] = None) -> "ScanNode":
        name = data["n"]
        is_dir = data["d"]
        if is_dir:
            ext, cat = "", "Folder"
            col = data.get("col") or VIBRANT_FOLDER_PALETTE[abs(hash(name)) % len(VIBRANT_FOLDER_PALETTE)]
        else:
            ext, cat, default_col = classify_extension(name)
            col = data.get("col") or default_col
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
            color=VIBRANT_FOLDER_PALETTE[abs(hash(root_name)) % len(VIBRANT_FOLDER_PALETTE)],
        )
        self._scan_recursive(root_node, depth=0)
        return root_node

    def _scan_recursive(self, dir_node: ScanNode, depth: int = 0) -> None:
        if self.cancel_check and self.cancel_check():
            return
        if depth > 1000:
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
                                color=VIBRANT_FOLDER_PALETTE[abs(hash(entry.name)) % len(VIBRANT_FOLDER_PALETTE)],
                            )
                            self._scan_recursive(sub_node, depth + 1)
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
                        color="#6c757d",
                        file_count=len(rem_children),
                    )
                )
            children = kept

        dir_node.children = children
        dir_node.size = total_size
        dir_node.file_count = total_files
        dir_node.dir_count = total_dirs


def run_admin_scan_worker(target_path: str, filter_virtual: bool) -> int:
    """Robust Polkit worker writing to a temporary gzip file (prevents pipe deadlock and crashes)."""
    try:
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
        tmp_fd, tmp_file = tempfile.mkstemp(prefix="wiztree_admin_", suffix=".json.gz")
        os.close(tmp_fd)

        with gzip.open(tmp_file, "wt", encoding="utf-8") as gf:
            json.dump(payload_dict, gf, ensure_ascii=False)

        os.chmod(tmp_file, 0o644)
        sys.stdout.write(f"DONE\t{tmp_file}\n")
        sys.stdout.flush()
        return 0
    except Exception as e:
        sys.stderr.write(f"Worker Exception: {e}\n")
        sys.stderr.flush()
        return 1


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
        color="#3a86ff",
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
            color=color,  # Keep brilliant extension category color!
            file_count=len(file_list_sorted),
            dir_count=0,
        )
        g_node.children = file_list_sorted[:250]
        group_nodes.append(g_node)

    group_nodes.sort(key=lambda g: g.size, reverse=True)
    virtual_root.children = group_nodes
    return virtual_root


# ==============================================================================
# Custom High-Res Desktop Icon Generation (3D Glowing Treemap Disk)
# ==============================================================================

CUSTOM_ICON_PNG_B64 = """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"""

def install_custom_icons() -> str:
    icons_dir = os.path.expanduser("~/.local/share/icons")
    os.makedirs(icons_dir, exist_ok=True)
    png_path = os.path.join(icons_dir, "wiztree-ubuntu.png")
    try:
        raw_png = base64.b64decode(CUSTOM_ICON_PNG_B64.strip())
        with open(png_path, "wb") as f:
            f.write(raw_png)
        hicolor_256 = os.path.expanduser("~/.local/share/icons/hicolor/256x256/apps")
        os.makedirs(hicolor_256, exist_ok=True)
        shutil.copy2(png_path, os.path.join(hicolor_256, "wiztree-ubuntu.png"))
        subprocess.run(["gtk-update-icon-cache", "-f", "-t", os.path.expanduser("~/.local/share/icons/hicolor")], stderr=subprocess.DEVNULL)
    except Exception as e:
        print(f"[!] Warning installing icon: {e}")
    return png_path


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
            created_paths.append(shortcut_file)
            try:
                subprocess.run(["gio", "set", shortcut_file, "metadata::trusted", "true"], stderr=subprocess.DEVNULL)
            except Exception:
                pass
        except Exception as e:
            print(f"[!] Warning writing shortcut to {shortcut_file}: {e}")

    apps_dir = os.path.expanduser("~/.local/share/applications")
    os.makedirs(apps_dir, exist_ok=True)
    menu_file = os.path.join(apps_dir, "wiztree-ubuntu.desktop")
    try:
        with open(menu_file, "w", encoding="utf-8") as f:
            f.write(desktop_content)
        os.chmod(menu_file, 0o755)
        created_paths.append(menu_file)
        try:
            subprocess.run(["update-desktop-database", apps_dir], stderr=subprocess.DEVNULL)
        except Exception:
            pass
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
        "~/.local/bin/file_shredder_gui.py was not found.\n"
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
            QTextEdit, QCheckBox, QComboBox, QStackedWidget, QLineEdit, QSizePolicy,
            QScrollArea
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
            self.proc = None

        def cancel(self):
            self._cancelled = True
            if self.proc:
                try:
                    self.proc.terminate()
                except Exception:
                    pass

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
                    self.proc = subprocess.Popen(
                        cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        bufsize=1,
                    )
                    tmp_result_path = None
                    for line in self.proc.stdout:
                        if self._cancelled:
                            self.proc.terminate()
                            return
                        line = line.strip()
                        if line.startswith("PROGRESS\t"):
                            parts = line.split("\t", 3)
                            if len(parts) == 4:
                                self.progress.emit(int(parts[1]), int(parts[2]), parts[3])
                        elif line.startswith("DONE\t"):
                            tmp_result_path = line.split("\t", 1)[1].strip()

                    self.proc.wait()
                    if self.proc.returncode != 0 or not tmp_result_path or not os.path.exists(tmp_result_path):
                        err_msg = self.proc.stderr.read().strip() if self.proc.stderr else ""
                        self.failed_scan.emit(
                            err_msg or "Administrator authentication was canceled or failed."
                        )
                        return

                    # Safely read and decompress the file-based payload
                    with gzip.open(tmp_result_path, "rt", encoding="utf-8") as gf:
                        payload = json.load(gf)

                    try:
                        os.remove(tmp_result_path)
                    except Exception:
                        pass

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
        """High-DPI Cushioned Squarified Treemap with 100% Vibrant Color Support."""
        nodes_selected = pyqtSignal(list)
        node_zoomed = pyqtSignal(object)
        context_action_requested = pyqtSignal(list, QPointF)

        def __init__(self):
            super().__init__()
            self.setMouseTracking(True)
            self.setMinimumSize(320, 260)
            self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)

            self.current_root: Optional[ScanNode] = None
            self.rects: List[TreemapRect] = []
            self.hovered_node: Optional[ScanNode] = None
            self.selected_nodes: List[ScanNode] = []
            self.color_by_folder: bool = False
            self.filter_query: str = ""

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

            margin = 5.0
            w = max(0.0, float(self.width()) - 2 * margin)
            h = max(0.0, float(self.height()) - 2 * margin)
            if w <= 10 or h <= 10:
                return

            top_children = [c for c in self.current_root.children if c.size > 0]
            if not top_children:
                return

            top_layout = squarify_layout(top_children, margin, margin, w, h)
            q = self.filter_query

            for idx, (child, cx, cy, cw, ch) in enumerate(top_layout):
                if cw < 1.5 or ch < 1.5:
                    continue

                if self.color_by_folder:
                    child_folder_color = VIBRANT_FOLDER_PALETTE[idx % len(VIBRANT_FOLDER_PALETTE)]
                else:
                    child_folder_color = get_node_color(child, idx)

                child_matches = node_or_descendant_matches(child, q) if q else True

                if child.is_dir and child.children and cw >= 36 and ch >= 36:
                    header_h = 18.0 if ch >= 48 else 13.0
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
                    inner_pad = 2.5
                    ix = cx + inner_pad
                    iy = cy + header_h + 1.0
                    iw = max(0.0, cw - 2 * inner_pad)
                    ih = max(0.0, ch - header_h - inner_pad - 1.0)
                    sub_layout = squarify_layout(child.children, ix, iy, iw, ih)
                    for sub_idx, (sub_node, sx, sy, sw, sh) in enumerate(sub_layout):
                        if sw < 1.2 or sh < 1.2:
                            continue
                        if self.color_by_folder:
                            sub_node.color = child_folder_color
                        elif not sub_node.color or sub_node.color in ("#3b4252", "#3d5a80"):
                            sub_node.color = get_node_color(sub_node, sub_idx)
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
                    if self.color_by_folder:
                        child.color = child_folder_color
                    elif not child.color or child.color in ("#3b4252", "#3d5a80"):
                        child.color = get_node_color(child, idx)
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
                font.setPointSize(11)
                painter.setFont(font)
                painter.drawText(
                    self.rect(),
                    Qt.AlignmentFlag.AlignCenter,
                    "Select a folder or drive above and click 'Scan' or 'Search as Admin' to render the Treemap.\n"
                    "Tip: Drag mouse across the map for Windows-style blue multi-selection!",
                )
                painter.end()
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
                    dim_factor = 0.25

                # 100% Vibrant Color Restoration
                base_hex = get_node_color(r.node)
                base_color = QColor(base_hex)
                if is_hovered or is_selected:
                    base_color = base_color.lighter(125)

                if r.is_group_header:
                    frame_rect = QRectF(rx + 0.5, ry + 0.5, rw - 1.0, rh - 1.0)
                    bg_col = base_color.darker(250)
                    if dim_factor < 1.0:
                        bg_col.setAlphaF(dim_factor)
                    painter.fillRect(frame_rect, bg_col)

                    header_h = min(18.0, rh)
                    header_rect = QRectF(rx + 0.5, ry + 0.5, rw - 1.0, header_h)
                    h_grad = QLinearGradient(header_rect.topLeft(), header_rect.bottomLeft())
                    h_c1 = base_color.lighter(115 if is_hovered else 100)
                    h_c2 = base_color.darker(135)
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

                    if rw >= 45 and header_h >= 12:
                        text_col = QColor("#f0f6fc")
                        if dim_factor < 1.0:
                            text_col.setAlphaF(0.4)
                        painter.setPen(text_col)
                        f = painter.font()
                        f.setBold(True)
                        f.setPointSize(8)
                        painter.setFont(f)
                        h_fm = QFontMetrics(f)
                        label_str = f"📁 {bidi_isolate(r.node.name)}  ({format_size(r.node.size)})"
                        elided = h_fm.elidedText(label_str, Qt.TextElideMode.ElideRight, int(rw - 8))
                        painter.drawText(
                            QRectF(rx + 4, ry + 1, rw - 8, header_h - 2),
                            Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft,
                            elided,
                        )
                else:
                    pad = 0.75 if (rw > 3 and rh > 3) else 0.0
                    block_rect = QRectF(rx + pad, ry + pad, max(0.5, rw - 2 * pad), max(0.5, rh - 2 * pad))

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

                    if rw >= 40 and rh >= 18:
                        f = painter.font()
                        f.setBold(is_selected or (has_active_filter and is_match))
                        f.setPointSize(8 if rh < 32 else 9)
                        painter.setFont(f)
                        b_fm = QFontMetrics(f)

                        name_isolated = bidi_isolate(r.node.name)
                        size_str = format_size(r.node.size)
                        text_rect = QRectF(block_rect.x() + 3, block_rect.y() + 2, block_rect.width() - 6, block_rect.height() - 4)

                        text_color = QColor("#ffffff")
                        if dim_factor < 1.0:
                            text_color = QColor("#5b6573")

                        painter.setPen(text_color)
                        if rh >= 32 and rw >= 60:
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

            if self.is_rubber_banding:
                sel_box = self._get_selection_box()
                painter.fillRect(sel_box, QColor(0, 120, 215, 65))
                painter.setPen(QPen(QColor(0, 120, 215, 230), 1.5, Qt.PenStyle.SolidLine))
                painter.drawRect(sel_box)
            painter.end()

    class WizTreeUbuntuMainWindow(QMainWindow):
        def __init__(self, start_path: Optional[str] = None):
            super().__init__()
            self.setWindowTitle("WizTree Ubuntu Edition — Visual Treemap Disk Space Analyzer")

            # Dynamic responsive sizing for any laptop or monitor
            self.setMinimumSize(820, 520)
            screen = QApplication.primaryScreen()
            if screen:
                avail = screen.availableGeometry()
                w = min(1120, max(840, avail.width() - 40))
                h = min(680, max(520, avail.height() - 60))
                self.resize(w, h)
            else:
                self.resize(1080, 680)

            self.raw_scan_root: Optional[ScanNode] = None
            self.display_root: Optional[ScanNode] = None
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
                    font-size: 9.5pt;
                }
                QFrame#CardFrame {
                    background-color: #161b22;
                    border: 1px solid #30363d;
                    border-radius: 6px;
                }
                QPushButton {
                    background-color: #21262d;
                    color: #e6edf3;
                    border: 1px solid #363b42;
                    border-radius: 5px;
                    padding: 4px 10px;
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
                    border-radius: 5px;
                    padding: 3px 6px;
                }
                QLineEdit:focus {
                    border: 1px solid #0078d7;
                }
                QHeaderView::section {
                    background-color: #161b22;
                    color: #8b949e;
                    border: none;
                    border-bottom: 1px solid #30363d;
                    padding: 4px;
                    font-weight: bold;
                }
                QProgressBar {
                    background-color: #0d1117;
                    border: 1px solid #30363d;
                    border-radius: 4px;
                    text-align: center;
                    color: #ffffff;
                    height: 16px;
                }
                QProgressBar::chunk {
                    background-color: #0078d7;
                    border-radius: 3px;
                }
                QScrollArea {
                    border: none;
                    background-color: transparent;
                }
                """
            )

        def _build_ui(self):
            central = QWidget()
            self.setCentralWidget(central)
            main_layout = QVBoxLayout(central)
            main_layout.setContentsMargins(8, 8, 8, 8)
            main_layout.setSpacing(6)

            # 1. Compact 2-Row Top Control Toolbar (Never overflows screen)
            top_bar = QFrame()
            top_bar.setObjectName("CardFrame")
            top_vbox = QVBoxLayout(top_bar)
            top_vbox.setContentsMargins(8, 6, 8, 6)
            top_vbox.setSpacing(6)

            # Row 1: Target Path & Scan Actions
            row1 = QHBoxLayout()
            row1.setSpacing(6)
            lbl_target = QLabel("<b>Target:</b>")
            self.path_input = QLineEdit(self.target_scan_path)
            self.path_input.setMinimumWidth(180)

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
            btn_desktop_icon.setToolTip("Creates a trusted, clickable shortcut icon on your Ubuntu Desktop ('עמוד הבית')")
            btn_desktop_icon.clicked.connect(self._action_create_desktop_shortcut)

            row1.addWidget(lbl_target)
            row1.addWidget(self.path_input, 1)
            row1.addWidget(btn_browse)
            row1.addWidget(btn_scan)
            row1.addWidget(btn_admin_scan)
            row1.addWidget(btn_desktop_icon)
            top_vbox.addLayout(row1)

            # Row 2: Distribution Mode, Filter & Toggles
            row2 = QHBoxLayout()
            row2.setSpacing(6)

            lbl_mode = QLabel("<b>Mode:</b>")
            self.mode_combo = QComboBox()
            self.mode_combo.addItem("📁 By Folders (Hierarchy)", "folders")
            self.mode_combo.addItem("🎨 By File Types (Extensions)", "filetypes")
            self.mode_combo.currentIndexChanged.connect(self._on_distribution_mode_changed)

            self.chk_color_folders = QCheckBox("Color by Folder")
            self.chk_color_folders.setToolTip("Colors blocks by parent folder hierarchy")
            self.chk_color_folders.toggled.connect(self._on_color_mode_changed)

            self.chk_filter_virtual = QCheckBox("Skip Virtual")
            self.chk_filter_virtual.setChecked(True)
            self.chk_filter_virtual.setToolTip("Filters out virtual filesystems (/proc, /sys, /snap) for accurate totals")

            lbl_f_icon = QLabel("<b>🔍 Search:</b>")
            lbl_f_icon.setStyleSheet("color: #00f5d4;")

            self.filter_input = QLineEdit()
            self.filter_input.setPlaceholderText("Filter name, *.iso, *.mp4, or Hebrew keyword...")
            self.filter_input.setClearButtonEnabled(True)
            self.filter_input.textChanged.connect(self._on_filter_changed)

            self.filter_mode_combo = QComboBox()
            self.filter_mode_combo.addItem("✨ Highlight", "highlight")
            self.filter_mode_combo.addItem("🎯 Isolate", "isolate")
            self.filter_mode_combo.currentIndexChanged.connect(self._on_filter_changed)

            self.lbl_filter_stats = QLabel("Tip: Drag mouse for blue multi-selection")
            self.lbl_filter_stats.setStyleSheet("color: #8b949e; font-size: 8.5pt;")

            btn_clear_filter = QPushButton("✕ Clear")
            btn_clear_filter.clicked.connect(lambda: self.filter_input.clear())

            row2.addWidget(lbl_mode)
            row2.addWidget(self.mode_combo)
            row2.addWidget(self.chk_color_folders)
            row2.addWidget(self.chk_filter_virtual)
            row2.addSpacing(6)
            row2.addWidget(lbl_f_icon)
            row2.addWidget(self.filter_input, 1)
            row2.addWidget(self.filter_mode_combo)
            row2.addWidget(self.lbl_filter_stats)
            row2.addWidget(btn_clear_filter)
            top_vbox.addLayout(row2)

            main_layout.addWidget(top_bar)

            # 2. Breadcrumb & Legend Bar
            nav_bar = QFrame()
            nav_bar.setObjectName("CardFrame")
            nav_layout = QHBoxLayout(nav_bar)
            nav_layout.setContentsMargins(8, 4, 8, 4)
            nav_layout.setSpacing(6)

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
                badge.setStyleSheet("font-size: 8.5pt; padding-left: 3px;")
                nav_layout.addWidget(badge)

            main_layout.addWidget(nav_bar)

            # 3. Main Workspace Splitter: Treemap (Left ~75%) vs Scrollable Inspector (Right ~25%)
            splitter = QSplitter(Qt.Orientation.Horizontal)

            treemap_frame = QFrame()
            treemap_frame.setObjectName("CardFrame")
            tm_layout = QVBoxLayout(treemap_frame)
            tm_layout.setContentsMargins(4, 4, 4, 4)
            self.treemap = TreemapCanvas()
            self.treemap.nodes_selected.connect(self._on_nodes_selected)
            self.treemap.node_zoomed.connect(self._on_node_zoomed)
            self.treemap.context_action_requested.connect(self._show_context_menu)
            tm_layout.addWidget(self.treemap)
            splitter.addWidget(treemap_frame)

            # Right Panel: Wrapped inside QScrollArea so it never forces window height
            scroll_inspector = QScrollArea()
            scroll_inspector.setWidgetResizable(True)
            scroll_inspector.setMinimumWidth(260)

            inspector_content = QWidget()
            insp_layout = QVBoxLayout(inspector_content)
            insp_layout.setContentsMargins(8, 8, 8, 8)
            insp_layout.setSpacing(6)

            insp_header = QLabel("<b>🔍 File Inspector & Details</b>")
            insp_header.setStyleSheet("font-size: 10.5pt; color: #58a6ff;")
            insp_layout.addWidget(insp_header)

            self.lbl_sel_name = QLabel("Select any block on the Treemap or drag with mouse")
            self.lbl_sel_name.setWordWrap(True)
            self.lbl_sel_name.setStyleSheet("font-size: 10pt; font-weight: bold; color: #ffffff;")
            self.lbl_sel_name.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            insp_layout.addWidget(self.lbl_sel_name)

            self.lbl_sel_meta = QLabel("")
            self.lbl_sel_meta.setWordWrap(True)
            self.lbl_sel_meta.setStyleSheet("color: #8b949e; font-size: 9pt;")
            self.lbl_sel_meta.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            insp_layout.addWidget(self.lbl_sel_meta)

            act_row1 = QHBoxLayout()
            self.btn_open_item = QPushButton("📂 Open")
            self.btn_open_item.clicked.connect(self._action_open_selected)
            self.btn_reveal_item = QPushButton("🧭 Reveal in Files")
            self.btn_reveal_item.clicked.connect(self._action_reveal_selected)
            act_row1.addWidget(self.btn_open_item)
            act_row1.addWidget(self.btn_reveal_item)
            insp_layout.addLayout(act_row1)

            act_row2 = QHBoxLayout()
            self.btn_shred_gui = QPushButton("🔥 Shredder")
            self.btn_shred_gui.setObjectName("ShredBtn")
            self.btn_shred_gui.clicked.connect(self._action_send_to_shredder)

            self.btn_quick_shred = QPushButton("⚡ Shred (3-Pass)")
            self.btn_quick_shred.clicked.connect(self._action_quick_shred)
            act_row2.addWidget(self.btn_shred_gui)
            act_row2.addWidget(self.btn_quick_shred)
            insp_layout.addLayout(act_row2)

            lbl_prev_title = QLabel("<b>Live Preview:</b>")
            insp_layout.addWidget(lbl_prev_title)

            self.preview_stack = QStackedWidget()
            self.preview_stack.setFixedHeight(140)

            self.text_preview = QTextEdit()
            self.text_preview.setReadOnly(True)
            self.text_preview.setPlaceholderText("Click or drag-select files on the Treemap to preview them here...")
            self.preview_stack.addWidget(self.text_preview)

            self.image_preview_lbl = QLabel()
            self.image_preview_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self.image_preview_lbl.setStyleSheet("background-color: #0d1117; border: 1px solid #30363d; border-radius: 5px;")
            self.preview_stack.addWidget(self.image_preview_lbl)

            insp_layout.addWidget(self.preview_stack)

            self.lbl_table_title = QLabel("<b>Largest Items:</b>")
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

            scroll_inspector.setWidget(inspector_content)
            splitter.addWidget(scroll_inspector)

            splitter.setStretchFactor(0, 75)
            splitter.setStretchFactor(1, 25)
            main_layout.addWidget(splitter, 1)

            # 4. Bottom Status & Progress Bar
            status_bar = QFrame()
            status_bar.setObjectName("CardFrame")
            status_layout = QHBoxLayout(status_bar)
            status_layout.setContentsMargins(8, 3, 8, 3)

            self.lbl_status = QLabel("Ready. Drag mouse on the Treemap for Windows-style blue multi-selection.")
            self.progress_bar = QProgressBar()
            self.progress_bar.setFixedWidth(200)
            self.progress_bar.setVisible(False)

            status_layout.addWidget(self.lbl_status, 1)
            status_layout.addWidget(self.progress_bar)
            main_layout.addWidget(status_bar)

            self._table_nodes: List[ScanNode] = []

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
                self.lbl_filter_stats.setText("Tip: Drag mouse for blue selection")
                self.treemap.set_root_node(
                    current_base,
                    color_by_folder=self.chk_color_folders.isChecked(),
                    filter_query="",
                )
                self._update_inspector_table(self.current_selected_nodes or [current_base], current_base)
                return

            _, count, num_bytes = build_filtered_isolated_tree(current_base, query)
            pct = (num_bytes / current_base.size * 100.0) if current_base.size > 0 else 0.0
            self.lbl_filter_stats.setText(f"Matched: {count:,} ({format_size(num_bytes)} • {pct:.1f}%)")

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
                    f"<b>Size:</b> {format_size(node.size)} ({node.size:,} B • {pct:.2f}%)<br/>"
                    f"<b>Path:</b> {bidi_isolate(node.path)}<br/>"
                    f"<b>Category:</b> {node.category} &nbsp;|&nbsp; <b>Modified:</b> {mtime_str}<br/>"
                    f"<b>Permissions:</b> <code>{perms_str}</code> &nbsp;|&nbsp; <b>Owner:</b> {owner_str}"
                )
                self.btn_open_item.setText("📂 Open")
                self.btn_reveal_item.setText("🧭 Reveal")
                self.btn_shred_gui.setText("🔥 Shredder")
                self.btn_quick_shred.setText("⚡ Shred (3-Pass)")
                self._update_live_preview(node)

            else:
                total_size = sum(n.size for n in self.current_selected_nodes)
                pct = (total_size / view_root.size * 100.0) if (view_root and view_root.size > 0) else 100.0
                num_files = sum(1 for n in self.current_selected_nodes if not n.is_dir)
                num_dirs = sum(1 for n in self.current_selected_nodes if n.is_dir)

                self.lbl_sel_name.setText(f"📦 Blue Box Selection ({count:,} items)")
                self.lbl_sel_meta.setText(
                    f"<b>Combined Size:</b> {format_size(total_size)} ({total_size:,} B • {pct:.2f}%)<br/>"
                    f"<b>Contents:</b> {num_files:,} files and {num_dirs:,} folders selected"
                )
                self.btn_open_item.setText(f"📂 Open All ({count})")
                self.btn_reveal_item.setText("🧭 Reveal First")
                self.btn_shred_gui.setText(f"🔥 Send All ({count})")
                self.btn_quick_shred.setText(f"⚡ Batch Shred ({count})")

                self.preview_stack.setCurrentIndex(0)
                summary_lines = [
                    f"=== Selected Items ({count:,}) ===",
                    f"Total Combined Size: {format_size(total_size)}",
                    f"Files: {num_files:,} | Folders: {num_dirs:,}",
                    "",
                    "Selected items:",
                ]
                for n in self.current_selected_nodes[:30]:
                    p = "📁" if n.is_dir else "📄"
                    summary_lines.append(f" {p} {bidi_isolate(n.name)}  ({format_size(n.size)})")
                if count > 30:
                    summary_lines.append(f" ... and {count - 30} more items.")
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
                        QSize(280, 130),
                        Qt.AspectRatioMode.KeepAspectRatio,
                        Qt.TransformationMode.SmoothTransformation,
                    )
                    self.image_preview_lbl.setPixmap(scaled)
                    return

            self.preview_stack.setCurrentIndex(0)
            try:
                with open(fp, "rb") as f:
                    sample = f.read(4096)
                if b"\x00" in sample[:256]:
                    hex_head = " ".join(f"{b:02X}" for b in sample[:64])
                    self.text_preview.setPlainText(
                        f"[Binary File — {node.category} ({ext})]\n\n"
                        f"First bytes (Hex):\n{hex_head}"
                    )
                else:
                    text_content = sample.decode("utf-8", errors="replace")
                    self.text_preview.setPlainText(text_content)
            except PermissionError:
                self.text_preview.setPlainText("🔒 Permission Denied to preview file contents.")
            except Exception as e:
                self.text_preview.setPlainText(f"Cannot preview file: {e}")

        def _update_inspector_table(self, nodes: List[ScanNode], view_root: ScanNode):
            if not nodes:
                return

            if len(nodes) > 1:
                self.lbl_table_title.setText(f"<b>Selected Items ({len(nodes):,} items):</b>")
                children = sorted(nodes, key=lambda c: c.size, reverse=True)[:50]
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
                    children = matching_first[:50]
                else:
                    children = raw_children[:50]
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