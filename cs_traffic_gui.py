"""Desktop GUI for authorized Cobalt Strike Beacon traffic analysis."""

import queue
import sys
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

import cs_traffic_report


BG = "#0b1220"
PANEL = "#111c2e"
PANEL_2 = "#16253b"
TEXT = "#dce8f5"
MUTED = "#8298b2"
CYAN = "#45d7e8"
GREEN = "#73e6b1"
RED = "#ff7187"
VERSION = "1.0.0"


class TrafficGui(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"CS Beacon // 流量分析工具 v{VERSION}")
        self.geometry("1120x760")
        self.minsize(860, 560)
        self.configure(bg=BG)
        self.events = queue.Queue()
        self._build_style()
        self._build_ui()
        self.after(100, self._drain_events)

    def _build_style(self):
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("TFrame", background=BG)
        style.configure("Panel.TFrame", background=PANEL)
        style.configure("TLabel", background=BG, foreground=TEXT, font=("Segoe UI", 10))
        style.configure("Title.TLabel", background=BG, foreground=TEXT, font=("Segoe UI", 22, "bold"))
        style.configure("Sub.TLabel", background=BG, foreground=MUTED, font=("Consolas", 9))
        style.configure("TButton", background=PANEL_2, foreground=TEXT, borderwidth=0, padding=(12, 8))
        style.map("TButton", background=[("active", "#203a59")], foreground=[("active", CYAN)])
        style.configure("Accent.TButton", background="#16495a", foreground=CYAN, padding=(18, 9))
        style.map("Accent.TButton", background=[("active", "#1c6575")])
        style.configure("TEntry", fieldbackground=PANEL_2, foreground=TEXT, insertcolor=CYAN, borderwidth=0, padding=7)
        style.configure("Status.TLabel", background=PANEL, foreground=GREEN, padding=8)

    def _build_ui(self):
        header = ttk.Frame(self)
        header.pack(fill="x", padx=28, pady=(24, 14))
        ttk.Label(header, text="CS BEACON 流量分析", style="Title.TLabel").pack(anchor="w")
        ttk.Label(header, text=f"V{VERSION}  /  授权流量分析  /  PCAPNG 解密", style="Sub.TLabel").pack(anchor="w", pady=(3, 0))

        controls = ttk.Frame(self, style="Panel.TFrame", padding=16)
        controls.pack(fill="x", padx=28, pady=8)
        controls.columnconfigure(1, weight=1)
        self.pcap = tk.StringVar(value="")
        self.keys = tk.StringVar(value="cobaltstrike.beacon_keys")
        self.output = tk.StringVar(value="")
        self._path_row(controls, 0, "抓包文件", self.pcap, self._pick_pcap)
        self._path_row(controls, 1, "密钥文件", self.keys, self._pick_keys)
        self._path_row(controls, 2, "报告文件", self.output, self._pick_output, optional=True)
        actions = ttk.Frame(controls, style="Panel.TFrame")
        actions.grid(row=3, column=0, columnspan=3, sticky="e", pady=(12, 0))
        self.run_button = ttk.Button(actions, text="▶  开始分析", style="Accent.TButton", command=self._start)
        self.run_button.pack(side="right")
        ttk.Button(actions, text="清空结果", command=self._clear).pack(side="right", padx=(0, 8))

        output_panel = ttk.Frame(self, style="Panel.TFrame", padding=(16, 12))
        output_panel.pack(fill="both", expand=True, padx=28, pady=(8, 0))
        output_panel.rowconfigure(1, weight=1)
        output_panel.columnconfigure(0, weight=1)
        ttk.Label(output_panel, text="实时分析结果", style="Sub.TLabel").grid(row=0, column=0, sticky="w", pady=(0, 8))
        text_frame = tk.Frame(output_panel, bg=PANEL)
        text_frame.grid(row=1, column=0, sticky="nsew")
        self.text = tk.Text(text_frame, bg="#08101d", fg=TEXT, insertbackground=CYAN, selectbackground="#24526b", relief="flat", wrap="word", font=("Consolas", 10), padx=14, pady=12)
        scroll = ttk.Scrollbar(text_frame, orient="vertical", command=self.text.yview)
        self.text.configure(yscrollcommand=scroll.set)
        self.text.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

        self.status = tk.StringVar(value="就绪 / 请选择抓包文件和密钥文件")
        ttk.Label(self, textvariable=self.status, style="Status.TLabel", anchor="w").pack(fill="x", padx=28, pady=(8, 18))

    def _path_row(self, parent, row, label, variable, command, optional=False):
        ttk.Label(parent, text=label, style="Sub.TLabel").grid(row=row, column=0, sticky="w", padx=(0, 18), pady=5)
        ttk.Entry(parent, textvariable=variable).grid(row=row, column=1, sticky="ew", pady=5)
        ttk.Button(parent, text="浏览", command=command).grid(row=row, column=2, padx=(10, 0), pady=5)

    def _pick_pcap(self):
        value = filedialog.askopenfilename(title="选择抓包文件", filetypes=[("抓包文件", "*.pcap *.pcapng"), ("所有文件", "*")])
        if value:
            self.pcap.set(value)

    def _pick_keys(self):
        value = filedialog.askopenfilename(title="选择密钥文件", filetypes=[("Beacon 密钥", "*.beacon_keys"), ("所有文件", "*")])
        if value:
            self.keys.set(value)

    def _pick_output(self):
        value = filedialog.asksaveasfilename(title="保存分析报告", defaultextension=".txt", filetypes=[("文本报告", "*.txt")])
        if value:
            self.output.set(value)

    def _clear(self):
        self.text.delete("1.0", "end")
        self.status.set("就绪 / 已清空分析结果")

    def _start(self):
        pcap = Path(self.pcap.get().strip())
        keys = Path(self.keys.get().strip())
        output = self.output.get().strip()
        if not pcap.is_file():
            messagebox.showerror("需要输入", "请选择有效的 PCAP 或 PCAPNG 文件。")
            return
        if not keys.is_file():
            messagebox.showerror("需要输入", "请选择有效的 beacon_keys 密钥文件。")
            return
        self.run_button.configure(state="disabled")
        self.status.set("分析中 / 正在重组 TCP 并解密 Beacon 数据...")
        self.text.delete("1.0", "end")
        threading.Thread(target=self._analyze, args=(pcap, keys, output), daemon=True).start()

    def _analyze(self, pcap, keys, output):
        try:
            report = cs_traffic_report.build_report(pcap, keys)
            if output:
                Path(output).write_text(report, encoding="utf-8")
            self.events.put(("done", report, output))
        except Exception as exc:  # surface parser errors in the GUI
            self.events.put(("error", f"{type(exc).__name__}: {exc}", ""))

    def _drain_events(self):
        try:
            kind, message, output = self.events.get_nowait()
            self.run_button.configure(state="normal")
            if kind == "done":
                self.text.insert("end", message)
                self.status.set("完成 / 报告已显示" + (f" / 已保存到 {output}" if output else ""))
            else:
                self.text.insert("end", message + "\n")
                self.status.set("错误 / 分析失败")
                messagebox.showerror("分析失败", message)
        except queue.Empty:
            pass
        self.after(100, self._drain_events)


if __name__ == "__main__":
    if sys.platform == "win32":
        # Keep the window crisp on high-DPI Windows displays.
        try:
            import ctypes

            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except (AttributeError, OSError):
            pass
    TrafficGui().mainloop()
