# WizTree Ubuntu Edition ⚡

> **High-Speed Visual Disk Space Analyzer with Cushioned Treemap for Ubuntu / Linux**  
> *A fast, beautiful, and feature-rich Linux alternative to WizTree & WinDirStat, featuring full Hebrew/BiDi filename support, real-time live filtering, and Windows-style marquee multi-selection.*

---

## ✨ Features

- **🚀 Ultra-Fast Scanning Engine**: Powered by optimized `os.scandir()` traversal that scans hundreds of thousands of files in seconds with minimal memory overhead.
- **🛡️ "Search as Admin" (Polkit / UAC Integration)**: Background worker using `pkexec` to scan protected system directories (`/root`, `/var/lib/docker`, etc.) without graphical Wayland/X11 permission issues.
- **🚫 Automatic Virtual Mount Filtering**: Automatically detects and ignores virtual and pseudofs mounts (`/proc`, `/sys`, `/dev`, `/run`, `/snap`, `tmpfs`, `squashfs`) to guarantee real physical disk statistics.
- **🎨 Interactive 3D Cushioned Squarified Treemap**:
  - **Distribution Toggle**: Switch on-the-fly between **By Folders (Hierarchy)** and **By File Types (Extensions)** without rescanning.
  - **Zoom / Drill-down**: Double-click any folder or category block to zoom into it; navigate with the breadcrumb bar.
  - **Color Coding**: WizTree-inspired high-contrast dark palette categorized into Video, Archives, Images, Audio, Documents, Code, and System.
- **🟦 Windows-Style Marquee Multi-Selection**: Click and drag across the Treemap with a translucent blue box to select multiple files at once for batch inspection, path copying, or batch shredding.
- **🔍 Real-Time Search & Live Filter Bar**:
  - Instant filter by name, extension (`*.iso`, `*.mp4`), or keyword.
  - **Highlight Mode**: Glows matching files on the Treemap while dimming non-matching blocks.
  - **Isolate Mode**: Re-renders the Treemap to show *only* matching files.
- **🇮🇱 Native Hebrew & Unicode BiDi Support**: Wrapped with Unicode Directional Isolates (`FSI`/`PDI`) so right-to-left Hebrew filenames never scramble surrounding English sizes, percentages, or paths.
- **🔍 In-Window File Inspector & Live Preview**:
  - Direct preview of images (`PNG`, `JPG`, `WebP`, `SVG`, `GIF`).
  - Integrated text and code preview for text files and logs.
  - Detailed metadata (permissions, owner, modification date, byte size).
- **🔥 File Shredder Integration**:
  - Direct integration with `~/.local/bin/file_shredder_gui.py` pre-populating target folder/file paths.
  - Built-in multi-pass (3-pass random + zero overwrite) shredder for individual or batch file destruction.
- **📌 Desktop Shortcut & Custom 3D Icon**: One-click launcher creation on your Desktop (`~/Desktop` / `~/שולחן העבודה`) and Applications menu with a custom glowing titanium icon.

---

## 📦 Quick Installation

### Prerequisites
Ubuntu 20.04 / 22.04 / 24.04 / 26.04 LTS (or any Debian-based distro).

### One-Command Setup
Open your terminal and run:

```bash
git clone [https://github.com/YOUR_USERNAME/wiztree-ubuntu.git](https://github.com/YOUR_USERNAME/wiztree-ubuntu.git)
cd wiztree-ubuntu
python3 wiztree_ubuntu.py --install

