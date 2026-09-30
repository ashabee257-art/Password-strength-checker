"""
Password Strength Checker - Desktop UI (Tkinter)
A Python-based cybersecurity awareness tool.

The password is analysed live, in memory only. It is never saved or sent anywhere.
Run:  python password_strength_checker_gui.py
(Tkinter comes built into Python on Windows and macOS.)
"""

import re
import tkinter as tk

# ---------- Palette ----------
BG = "#0F1B2D"       # window
PANEL = "#16273F"    # entry + checklist panels
LINE = "#26405F"     # borders, empty meter segments
TEXT = "#E6EEF8"
MUTED = "#8DA2BC"
GOOD = "#3DD68C"
BAD = "#E5484D"
STRENGTH_COLORS = {
    "WEAK": "#E5484D",
    "MEDIUM": "#F5A524",
    "STRONG": "#3DD68C",
    "VERY STRONG": "#4C9AFF",
}
STRENGTH_LEVEL = {"WEAK": 1, "MEDIUM": 2, "STRONG": 3, "VERY STRONG": 4}

FONT = "Segoe UI"

# ---------- Password logic ----------
COMMON_PASSWORDS = {
    "password", "password123", "12345678", "123456789", "123456",
    "qwerty", "qwerty123", "admin", "admin123", "abc123",
    "letmein", "welcome", "iloveyou",
}
SEQUENCES = [
    "123", "234", "345", "456", "567", "678", "789",
    "abc", "bcd", "cde", "qwe", "wer", "ert",
]

CHECK_LABELS = [
    "At least 8 characters",
    "12 or more characters (bonus point)",
    "Uppercase letter (A-Z)",
    "Lowercase letter (a-z)",
    "Number (0-9)",
    "Special character (@ # $ % !)",
    "Not a commonly used password",
    "No repeated characters (aaa, 111)",
    "No predictable sequence (123, abc)",
]


def analyze(password):
    """Return (score, strength, checks, feedback)."""
    score = 0
    feedback = []

    has_8 = len(password) >= 8
    has_12 = len(password) >= 12
    has_upper = bool(re.search(r"[A-Z]", password))
    has_lower = bool(re.search(r"[a-z]", password))
    has_digit = bool(re.search(r"\d", password))
    has_special = bool(re.search(r"[^A-Za-z0-9]", password))
    not_common = password.lower() not in COMMON_PASSWORDS
    no_repeat = not re.search(r"(.)\1\1", password)
    no_sequence = not any(s in password.lower() for s in SEQUENCES)

    if has_12:
        score += 2
    elif has_8:
        score += 1
        feedback.append("Use 12 or more characters for better security.")
    else:
        feedback.append("Use at least 8 characters.")

    for ok, point, tip in [
        (has_upper, 1, "Add at least one uppercase letter."),
        (has_lower, 1, "Add at least one lowercase letter."),
        (has_digit, 1, "Add at least one number."),
        (has_special, 1, "Add at least one special character."),
    ]:
        if ok:
            score += point
        else:
            feedback.append(tip)

    if not not_common:
        score = 0
        feedback.append("Avoid common or easily guessed passwords.")
    if not no_repeat:
        score = max(0, score - 1)
        feedback.append("Avoid repeating the same character many times.")
    if not no_sequence:
        score = max(0, score - 1)
        feedback.append("Avoid predictable sequences like 123 or abc.")

    if score <= 2:
        strength = "WEAK"
    elif score <= 4:
        strength = "MEDIUM"
    elif score == 5:
        strength = "STRONG"
    else:
        strength = "VERY STRONG"

    checks = [has_8, has_12, has_upper, has_lower, has_digit,
              has_special, not_common, no_repeat, no_sequence]
    return score, strength, checks, feedback


# ---------- UI ----------
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Password Strength Checker")
        self.configure(bg=BG)
        self.geometry("480x700")
        self.resizable(False, False)

        self.var = tk.StringVar()
        self.show = tk.BooleanVar(value=False)

        self._build_header()
        self._build_entry()
        self._build_meter()
        self._build_checklist()
        self._build_suggestions()
        self._build_footer()

        self.var.trace_add("write", lambda *_: self.refresh())
        self.refresh()
        self.entry.focus_set()

    # --- sections ---
    def _build_header(self):
        tk.Label(self, text="Password Strength Checker", bg=BG, fg=TEXT,
                 font=(FONT, 20, "bold")).pack(anchor="w", padx=28, pady=(26, 0))
        tk.Label(self, text="Type a password to see how well it holds up against guessing.",
                 bg=BG, fg=MUTED, font=(FONT, 10), wraplength=420,
                 justify="left").pack(anchor="w", padx=28, pady=(4, 16))

    def _build_entry(self):
        box = tk.Frame(self, bg=PANEL, highlightbackground=LINE, highlightthickness=1)
        box.pack(fill="x", padx=28)
        self.entry = tk.Entry(box, textvariable=self.var, show="•", bg=PANEL, fg=TEXT,
                              insertbackground=TEXT, relief="flat",
                              font=(FONT, 15), bd=0)
        self.entry.pack(fill="x", padx=14, pady=12)

        row = tk.Frame(self, bg=BG)
        row.pack(fill="x", padx=28, pady=(8, 0))
        tk.Checkbutton(row, text="Show password", variable=self.show,
                       command=self._toggle_show, bg=BG, fg=MUTED,
                       selectcolor=PANEL, activebackground=BG,
                       activeforeground=TEXT, font=(FONT, 9), bd=0,
                       highlightthickness=0).pack(side="left")
        tk.Button(row, text="Clear", command=lambda: self.var.set(""),
                  bg=BG, fg=MUTED, activebackground=BG, activeforeground=TEXT,
                  relief="flat", bd=0, cursor="hand2",
                  font=(FONT, 9, "underline")).pack(side="right")

    def _build_meter(self):
        self.canvas = tk.Canvas(self, width=424, height=10, bg=BG,
                                highlightthickness=0)
        self.canvas.pack(padx=28, pady=(20, 0))
        self.segments = []
        for i in range(4):
            x = i * 108
            self.segments.append(
                self.canvas.create_rectangle(x, 0, x + 100, 10, fill=LINE, width=0))

        info = tk.Frame(self, bg=BG)
        info.pack(fill="x", padx=28, pady=(10, 0))
        self.strength_lbl = tk.Label(info, text="", bg=BG, fg=MUTED,
                                     font=(FONT, 16, "bold"))
        self.strength_lbl.pack(side="left")
        self.score_lbl = tk.Label(info, text="", bg=BG, fg=MUTED, font=(FONT, 10))
        self.score_lbl.pack(side="right")

    def _build_checklist(self):
        panel = tk.Frame(self, bg=PANEL, highlightbackground=LINE, highlightthickness=1)
        panel.pack(fill="x", padx=28, pady=(18, 0))
        self.icons, self.texts = [], []
        for label in CHECK_LABELS:
            row = tk.Frame(panel, bg=PANEL)
            row.pack(fill="x", padx=14, pady=3)
            icon = tk.Label(row, text="•", width=2, bg=PANEL, fg=MUTED,
                            font=(FONT, 11, "bold"))
            icon.pack(side="left")
            txt = tk.Label(row, text=label, bg=PANEL, fg=MUTED, font=(FONT, 10))
            txt.pack(side="left")
            self.icons.append(icon)
            self.texts.append(txt)
        tk.Frame(panel, bg=PANEL, height=4).pack()

    def _build_suggestions(self):
        tk.Label(self, text="Suggestions", bg=BG, fg=TEXT,
                 font=(FONT, 11, "bold")).pack(anchor="w", padx=28, pady=(16, 2))
        self.sugg = tk.Label(self, text="", bg=BG, fg=MUTED, font=(FONT, 10),
                             wraplength=420, justify="left", anchor="nw")
        self.sugg.pack(fill="x", padx=28)

    def _build_footer(self):
        tk.Label(self, text="Checked on this computer only. Your password is never stored.",
                 bg=BG, fg=MUTED, font=(FONT, 9)).pack(side="bottom", pady=14)

    # --- behaviour ---
    def _toggle_show(self):
        self.entry.config(show="" if self.show.get() else "•")

    def refresh(self):
        password = self.var.get()

        if not password:
            for seg in self.segments:
                self.canvas.itemconfig(seg, fill=LINE)
            self.strength_lbl.config(text="Waiting for input", fg=MUTED)
            self.score_lbl.config(text="")
            for icon, txt in zip(self.icons, self.texts):
                icon.config(text="•", fg=MUTED)
                txt.config(fg=MUTED)
            self.sugg.config(text="Suggestions will appear as you type.", fg=MUTED)
            return

        score, strength, checks, feedback = analyze(password)
        color = STRENGTH_COLORS[strength]
        level = STRENGTH_LEVEL[strength]

        for i, seg in enumerate(self.segments):
            self.canvas.itemconfig(seg, fill=color if i < level else LINE)
        self.strength_lbl.config(text=strength.title(), fg=color)
        self.score_lbl.config(text=f"Score {score}/7  |  {len(password)} characters")

        for icon, txt, ok in zip(self.icons, self.texts, checks):
            icon.config(text="✓" if ok else "✗", fg=GOOD if ok else BAD)
            txt.config(fg=TEXT if ok else MUTED)

        if feedback:
            self.sugg.config(text="\n".join("- " + f for f in feedback), fg=TEXT)
        else:
            self.sugg.config(text="No basic weaknesses detected.", fg=GOOD)


if __name__ == "__main__":
    App().mainloop()
