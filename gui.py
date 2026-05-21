import sys, threading, queue, time, logging
from datetime import datetime, date
from pathlib import Path
from collections import Counter, defaultdict
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import yaml

sys.path.insert(0, str(Path(__file__).parent))

try:
    import matplotlib
    matplotlib.use('TkAgg')
    from matplotlib.figure import Figure
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
    HAS_MPL = True
except ImportError:
    HAS_MPL = False

# Дизайн
BG    = '#080d14'
PANEL = '#0d1520'
CARD  = '#111e2e'
BORDER= '#1a2d45'
MUTED = '#162030'
RED   = '#ef4444'
AMBER = '#f59e0b'
GREEN = '#22c55e'
BLUE  = '#3b82f6'
SKY   = '#7dd3fc'
TEXT  = '#e2e8f0'
DIM   = '#4a6080'
PURP  = '#a78bfa'
TEAL  = '#2dd4bf'

def mono(s=9):             return ('Courier', s)
def sans(s=10, bold=False): return ('Helvetica', s, 'bold') if bold else ('Helvetica', s)

SEV_COLOR = {'HIGH': RED, 'MEDIUM': AMBER, 'LOW': GREEN}


# Вспомогательные классы
class QueueLogHandler(logging.Handler):
    def __init__(self, q):
        super().__init__()
        self.q = q
        self.setFormatter(logging.Formatter('%(name)s — %(message)s'))

    def emit(self, record):
        self.q.put({'type': 'log', 'level': record.levelname,
                    'msg': self.format(record),
                    'time': datetime.now().strftime('%H:%M:%S')})


class GUINotifierProxy:
    def __init__(self, orig, q):
        self._orig = orig
        self._q    = q

    def notify(self, attacks):
        self._orig.notify(attacks)
        for a in attacks:
            self._q.put({'type': 'attack', 'data': dict(a),
                         'time': datetime.now().strftime('%H:%M:%S')})

    def __getattr__(self, n):
        return getattr(self._orig, n)


# Приложение
class BruteforceGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title('Bruteforce Detector')
        self.root.geometry('1300x800')
        self.root.minsize(1050, 680)
        self.root.configure(bg=BG)

        self._q            = queue.Queue()
        self._running      = False
        self._thread       = None
        self._log_handler  = None

        # Данные
        self._log_rows     = []          # [(vals_tuple, tag)]
        self._attack_rows  = []          # [(vals_tuple, sev, full_dict)]
        self._ip_stats     = {}          # ip -> {attempts, failed, success, proto}
        self._atk_type_cnt = Counter()
        self._proto_cnt    = Counter()
        self._timeline     = []          # [(datetime, sev)]
        self._today_attacks = 0
        self._ssh_attacks   = 0
        self._ftp_attacks   = 0
        self._stats = {'total': 0, 'failed': 0, 'success': 0,
                       'ips': set(), 'attacks': 0}

        # Сортировка
        self._sort_col     = 'time'
        self._sort_rev     = True
        self._atk_headers  = {}          # col -> base_text, заполняется позже

        # Тосты
        self._active_toasts = []
        self._chart_refresh_pending = False

        self._setup_styles()
        self._build_ui()
        self._poll_queue()

    # Стили
    def _setup_styles(self):
        s = ttk.Style(self.root)
        s.theme_use('clam')
        s.configure('.', background=BG, foreground=TEXT,
                    font=sans(10), borderwidth=0, relief='flat')
        s.configure('TFrame',        background=BG)
        s.configure('Card.TFrame',   background=CARD)
        s.configure('Panel.TFrame',  background=PANEL)
        s.configure('TLabel',        background=BG,    foreground=TEXT, font=sans(10))
        s.configure('TNotebook',     background=PANEL, borderwidth=0)
        s.configure('TNotebook.Tab', background=PANEL, foreground=DIM,
                    padding=[18, 9], font=sans(10))
        s.map('TNotebook.Tab',
              background=[('selected', CARD)],
              foreground=[('selected', TEXT)])
        s.configure('Treeview', background=PANEL, foreground=TEXT,
                    fieldbackground=PANEL, font=mono(9), rowheight=26, borderwidth=0)
        s.configure('Treeview.Heading', background=MUTED, foreground=SKY,
                    font=sans(9, True), relief='flat', padding=[5, 5])
        s.map('Treeview', background=[('selected', BORDER)])
        s.configure('Vertical.TScrollbar', background=MUTED,
                    troughcolor=PANEL, arrowcolor=DIM, borderwidth=0, width=10)

    # UI
    def _build_ui(self):
        self._build_header()
        self._nb = ttk.Notebook(self.root)
        self._nb.pack(fill='both', expand=True)
        self._build_dashboard_tab()
        self._build_logs_tab()
        self._build_attacks_tab()
        self._build_charts_tab()
        self._build_syslog_tab()
        self._build_settings_tab()
        self._build_statusbar()

    # Шапка
    def _build_header(self):
        hdr = tk.Frame(self.root, bg=PANEL, height=56)
        hdr.pack(fill='x')
        hdr.pack_propagate(False)
        tk.Label(hdr, text='◈', font=('Courier', 22), bg=PANEL, fg=RED
                 ).pack(side='left', padx=(14, 6))
        tk.Label(hdr, text='BRUTEFORCE DETECTOR', font=sans(13, True),
                 bg=PANEL, fg=TEXT).pack(side='left')
        tk.Label(hdr, text=' v2.0', font=sans(9), bg=PANEL, fg=DIM
                 ).pack(side='left', pady=2)
        self._lbl_status = tk.Label(hdr, text='● STOPPED',
                                    font=sans(10, True), bg=PANEL, fg=DIM)
        self._lbl_status.pack(side='right', padx=16)
        tk.Frame(self.root, bg=BORDER, height=1).pack(fill='x')

    # Дашборд
    def _build_dashboard_tab(self):
        tab = ttk.Frame(self._nb)
        self._nb.add(tab, text='  Dashboard  ')

        # Ряд 1: 4 карточки
        r1 = tk.Frame(tab, bg=BG)
        r1.pack(fill='x', padx=16, pady=(14, 6))
        self._sc_total   = self._stat_card(r1, 'ВСЕГО ЛОГОВ',   '0', SKY)
        self._sc_failed  = self._stat_card(r1, 'НЕУДАЧНЫХ',     '0', RED)
        self._sc_success = self._stat_card(r1, 'УСПЕШНЫХ',      '0', GREEN)
        self._sc_ips     = self._stat_card(r1, 'УНИКАЛЬНЫХ IP', '0', BLUE)
        for w in r1.winfo_children():
            w.pack(side='left', expand=True, fill='x', padx=(0, 10))

        # Ряд 2: 4 карточки
        r2 = tk.Frame(tab, bg=BG)
        r2.pack(fill='x', padx=16, pady=(0, 10))
        self._sc_attacks = self._stat_card(r2, 'ВСЕГО АТАК',   '0', AMBER)
        self._sc_today   = self._stat_card(r2, 'АТАК СЕГОДНЯ', '0', PURP)
        self._sc_ssh     = self._stat_card(r2, 'SSH АТАК',     '0', TEAL)
        self._sc_ftp     = self._stat_card(r2, 'FTP АТАК',     '0', RED)
        for w in r2.winfo_children():
            w.pack(side='left', expand=True, fill='x', padx=(0, 10))

        # Топ IP
        bot = tk.Frame(tab, bg=CARD)
        bot.pack(fill='both', expand=True, padx=16, pady=(0, 12))
        self._panel_title(bot, 'ТОП IP ПО ЧИСЛУ ПОПЫТОК ВХОДА')

        ip_cols = ('ip', 'attempts', 'failed', 'success', 'proto')
        ip_widths   = {'ip': 180, 'attempts': 110, 'failed': 110, 'success': 110, 'proto': 90}
        ip_headers  = {'ip': 'IP-адрес', 'attempts': 'Всего попыток',
                       'failed': 'Неудачных', 'success': 'Успешных', 'proto': 'Протокол'}
        tf = tk.Frame(bot, bg=CARD)
        tf.pack(fill='both', expand=True, padx=2, pady=(0, 2))
        self._ip_tree = ttk.Treeview(tf, columns=ip_cols, show='headings', height=9)
        for c in ip_cols:
            self._ip_tree.heading(c, text=ip_headers[c])
            self._ip_tree.column(c, width=ip_widths[c], anchor='center')
        vsb = ttk.Scrollbar(tf, orient='vertical', command=self._ip_tree.yview)
        self._ip_tree.configure(yscrollcommand=vsb.set)
        self._ip_tree.pack(side='left', fill='both', expand=True)
        vsb.pack(side='right', fill='y')
        self._ip_tree.tag_configure('hot',  foreground=RED)
        self._ip_tree.tag_configure('warm', foreground=AMBER)
        self._ip_tree.tag_configure('cool', foreground=TEXT)

    def _stat_card(self, parent, label, value, color):
        card = tk.Frame(parent, bg=CARD)
        tk.Frame(card, bg=color, height=3).pack(fill='x')
        tk.Label(card, text=label, font=sans(8), bg=CARD, fg=DIM
                 ).pack(anchor='w', padx=14, pady=(8, 0))
        lbl = tk.Label(card, text=value, font=sans(26, True), bg=CARD, fg=color)
        lbl.pack(anchor='w', padx=14, pady=(0, 10))
        return lbl

    def _panel_title(self, parent, text):
        tk.Label(parent, text=text, font=sans(9, True), bg=CARD, fg=SKY
                 ).pack(anchor='w', padx=12, pady=(10, 2))
        tk.Frame(parent, bg=BORDER, height=1).pack(fill='x', padx=12, pady=(0, 4))

    def _make_textbox(self, parent, tags):
        txt = tk.Text(parent, bg=CARD, fg=TEXT, font=mono(9),
                      insertbackground=TEXT, selectbackground=BORDER,
                      relief='flat', wrap='word', state='disabled', cursor='arrow')
        txt.pack(fill='both', expand=True, padx=2, pady=(0, 2))
        for tag, cfg in tags.items():
            txt.tag_configure(tag, **cfg)
        return txt

    # Live Logs
    def _build_logs_tab(self):
        tab = ttk.Frame(self._nb)
        self._nb.add(tab, text='  Live Logs  ')

        fbar = tk.Frame(tab, bg=PANEL, height=42)
        fbar.pack(fill='x')
        fbar.pack_propagate(False)
        tk.Label(fbar, text='Поиск:', bg=PANEL, fg=DIM, font=sans(9)
                 ).pack(side='left', padx=(12, 4))
        self._filter_var = tk.StringVar()
        self._filter_var.trace('w', self._apply_filter)
        tk.Entry(fbar, textvariable=self._filter_var, bg=MUTED, fg=TEXT,
                 insertbackground=TEXT, relief='flat', font=mono(9), width=26
                 ).pack(side='left', ipady=4)
        self._autoscroll_var = tk.BooleanVar(value=True)
        tk.Checkbutton(fbar, text='Автопрокрутка', variable=self._autoscroll_var,
                       bg=PANEL, fg=DIM, selectcolor=MUTED,
                       activebackground=PANEL, font=sans(9)
                       ).pack(side='right', padx=12)

        cols = ('time', 'ip', 'user', 'proto', 'status', 'details')
        widths  = {'time': 140, 'ip': 130, 'user': 120, 'proto': 65,
                   'status': 80, 'details': 400}
        headers = {'time': 'Время', 'ip': 'Source IP', 'user': 'Username',
                   'proto': 'Proto', 'status': 'Status', 'details': 'Details'}
        wrap = tk.Frame(tab, bg=BG)
        wrap.pack(fill='both', expand=True)
        self._log_tree = ttk.Treeview(wrap, columns=cols, show='headings')
        for c in cols:
            self._log_tree.heading(c, text=headers[c])
            self._log_tree.column(c, width=widths[c], anchor='w', stretch=(c == 'details'))
        vsb = ttk.Scrollbar(wrap, orient='vertical', command=self._log_tree.yview)
        self._log_tree.configure(yscrollcommand=vsb.set)
        self._log_tree.pack(side='left', fill='both', expand=True)
        vsb.pack(side='right', fill='y')
        self._log_tree.tag_configure('FAIL',    background='#1e0a0a', foreground=RED)
        self._log_tree.tag_configure('SUCCESS', background='#061a0e', foreground=GREEN)
        self._log_tree.tag_configure('even',    background=PANEL)
        self._log_tree.tag_configure('odd',     background=BG)

    # Attacks
    def _build_attacks_tab(self):
        tab = ttk.Frame(self._nb)
        self._nb.add(tab, text='  Attacks  ')

        top = tk.Frame(tab, bg=PANEL, height=42)
        top.pack(fill='x')
        top.pack_propagate(False)
        self._lbl_atk_count = tk.Label(top, text='Атак не обнаружено',
                                       bg=PANEL, fg=DIM, font=sans(10))
        self._lbl_atk_count.pack(side='left', padx=12, pady=10)
        tk.Label(top, text='клик на заголовок = сортировка  |  клик на строку = детали',
                 bg=PANEL, fg=DIM, font=sans(9)).pack(side='right', padx=14)

        self._atk_cols = ('time', 'sev', 'type', 'ip', 'user', 'reason', 'attempts')
        self._atk_headers = {
            'time': 'Время', 'sev': 'Severity', 'type': 'Тип атаки',
            'ip': 'IP', 'user': 'Пользователь', 'reason': 'Причина', 'attempts': 'Попытки'
        }
        widths = {'time': 80, 'sev': 75, 'type': 180, 'ip': 130,
                  'user': 110, 'reason': 300, 'attempts': 70}

        wrap = tk.Frame(tab, bg=BG)
        wrap.pack(fill='both', expand=True)
        self._atk_tree = ttk.Treeview(wrap, columns=self._atk_cols, show='headings')
        for c in self._atk_cols:
            self._atk_tree.heading(c, text=self._atk_headers[c],
                                   command=lambda col=c: self._sort_attacks(col))
            self._atk_tree.column(c, width=widths[c], anchor='w', stretch=(c == 'reason'))
        vsb = ttk.Scrollbar(wrap, orient='vertical', command=self._atk_tree.yview)
        self._atk_tree.configure(yscrollcommand=vsb.set)
        self._atk_tree.pack(side='left', fill='both', expand=True)
        vsb.pack(side='right', fill='y')
        self._atk_tree.tag_configure('HIGH',   background='#1f0808', foreground=RED)
        self._atk_tree.tag_configure('MEDIUM', background='#1f1408', foreground=AMBER)
        self._atk_tree.tag_configure('LOW',    background='#071a0e', foreground=GREEN)
        self._atk_tree.bind('<ButtonRelease-1>', self._on_attack_click)
        # Обновляем стрелку в заголовке по умолчанию
        self._update_sort_arrow()

    def _sort_attacks(self, col):
        if self._sort_col == col:
            self._sort_rev = not self._sort_rev
        else:
            self._sort_col = col
            self._sort_rev = False

        col_idx = self._atk_cols.index(col)

        def key(row):
            v = row[0][col_idx]
            try:    return (0, int(v))
            except: return (1, str(v).lower())

        self._attack_rows.sort(key=key, reverse=self._sort_rev)
        self._update_sort_arrow()
        self._rerender_attacks()

    def _update_sort_arrow(self):
        for c in self._atk_cols:
            arrow = (' ▼' if self._sort_rev else ' ▲') if c == self._sort_col else ''
            self._atk_tree.heading(c, text=self._atk_headers[c] + arrow,
                                   command=lambda col=c: self._sort_attacks(col))

    def _rerender_attacks(self):
        self._atk_tree.delete(*self._atk_tree.get_children())
        for vals, sev, _ in self._attack_rows:
            self._atk_tree.insert('', 'end', values=vals, tags=(sev,))

    def _on_attack_click(self, _event):
        sel = self._atk_tree.selection()
        if not sel:
            return
        idx = self._atk_tree.index(sel[0])
        if 0 <= idx < len(self._attack_rows):
            self._show_attack_detail(self._attack_rows[idx][2])

    def _show_attack_detail(self, attack: dict):
        win = tk.Toplevel(self.root)
        win.title('Детали атаки')
        win.geometry('660x560')
        win.configure(bg=BG)
        win.resizable(False, False)
        win.grab_set()

        sev       = attack.get('severity', 'MEDIUM')
        sev_color = SEV_COLOR.get(sev, AMBER)

        # Цветная шапка
        tk.Frame(win, bg=sev_color, height=4).pack(fill='x')
        title_bar = tk.Frame(win, bg=CARD)
        title_bar.pack(fill='x')
        tk.Label(title_bar,
                 text=f'  [{sev}]  {attack.get("type", "UNKNOWN").upper()}',
                 font=sans(13, True), bg=CARD, fg=sev_color
                 ).pack(side='left', padx=14, pady=12)
        tk.Button(title_bar, text='✕', command=win.destroy,
                  bg=CARD, fg=DIM, relief='flat', cursor='hand2',
                  font=sans(12)).pack(side='right', padx=10)

        # Таблица полей
        grid = tk.Frame(win, bg=CARD)
        grid.pack(fill='x', padx=16, pady=(0, 6))
        tk.Frame(grid, bg=BORDER, height=1).pack(fill='x')

        attempts = attack.get('failed_attempts', attack.get('attempts_in_window', '—'))
        window   = attack.get('time_window_seconds', '')
        window_s = f" за {window:.1f} сек" if isinstance(window, (int, float)) else ''
        rate     = attack.get('rate_per_second', None)
        t_range  = attack.get('time_range',
                   f"{attack.get('start_time', '')} — {attack.get('end_time', '')}")

        fields = [
            ('Протокол',             attack.get('log_type', '—').upper()),
            ('IP атакующего',        attack.get('source_ip', '—')),
            ('Цель (пользователь)',  attack.get('username', '—')),
            ('Неудачных попыток',    str(attempts)),
            ('Успешных попыток',     str(attack.get('success_attempts', '—'))),
            ('Уникальных IP',        str(attack.get('unique_ips', '—'))),
            ('Уникальных юзеров',    str(attack.get('unique_users', '—'))),
            ('Скорость атаки',       f"{rate:.1f} попыток/сек" if rate else '—'),
            ('Временной диапазон',   str(t_range)),
        ]
        for i, (label, value) in enumerate(fields):
            row_bg = CARD if i % 2 == 0 else MUTED
            row = tk.Frame(grid, bg=row_bg)
            row.pack(fill='x')
            tk.Label(row, text=label, width=24, anchor='w',
                     font=sans(9), bg=row_bg, fg=DIM).pack(side='left', padx=12, pady=4)
            tk.Label(row, text=value, anchor='w',
                     font=mono(9), bg=row_bg, fg=TEXT).pack(side='left', padx=4)

        # Блок причины срабатывания
        cf = tk.Frame(win, bg=CARD)
        cf.pack(fill='x', padx=16, pady=(0, 6))
        tk.Label(cf, text='Причина срабатывания', font=sans(9, True),
                 bg=CARD, fg=SKY).pack(anchor='w', padx=12, pady=(10, 3))
        tk.Frame(cf, bg=BORDER, height=1).pack(fill='x', padx=12)
        cause = (f"Сработало на {attempts} попыток{window_s}.\n"
                 f"Причина: {attack.get('reason', '—')}")
        tk.Label(cf, text=cause, justify='left', font=mono(9),
                 bg=CARD, fg=TEXT, wraplength=600
                 ).pack(anchor='w', padx=12, pady=(6, 10))

        # Блок рекомендаций
        rf = tk.Frame(win, bg=MUTED)
        rf.pack(fill='both', expand=True, padx=16, pady=(0, 16))
        tk.Label(rf, text='Рекомендации по борьбе с данным типом атак',
                 font=sans(9, True), bg=MUTED, fg=SKY
                 ).pack(anchor='w', padx=12, pady=(10, 3))
        tk.Frame(rf, bg=BORDER, height=1).pack(fill='x', padx=12)
        tk.Label(rf, text='In progress...', justify='left',
                 font=mono(9), bg=MUTED, fg=DIM, wraplength=600
                 ).pack(anchor='w', padx=12, pady=(8, 10))

    # Графики
    def _build_charts_tab(self):
        tab = ttk.Frame(self._nb)
        self._nb.add(tab, text='  Графики  ')

        tbar = tk.Frame(tab, bg=PANEL, height=42)
        tbar.pack(fill='x')
        tbar.pack_propagate(False)
        tk.Label(tbar, text='Статистика атак за сессию', font=sans(10, True),
                 bg=PANEL, fg=TEXT).pack(side='left', padx=14, pady=10)
        tk.Button(tbar, text='↻  Обновить', command=self._refresh_charts,
                  bg=MUTED, fg=SKY, relief='flat', font=sans(9),
                  cursor='hand2').pack(side='right', padx=12, pady=7)

        if not HAS_MPL:
            msg = tk.Frame(tab, bg=BG)
            msg.pack(expand=True)
            tk.Label(msg, text='matplotlib не установлен',
                     font=sans(14, True), bg=BG, fg=DIM).pack(pady=10)
            tk.Label(msg, text='pip install matplotlib',
                     font=mono(11), bg=BG, fg=AMBER).pack()
            return

        self._fig = Figure(figsize=(13, 6.2), facecolor=BG)
        self._fig.subplots_adjust(left=0.07, right=0.97,
                                  top=0.88, bottom=0.13,
                                  wspace=0.38, hspace=0.5)
        self._mpl_canvas = FigureCanvasTkAgg(self._fig, master=tab)
        self._mpl_canvas.get_tk_widget().pack(fill='both', expand=True)
        self._draw_empty_charts()

    def _draw_empty_charts(self):
        if not HAS_MPL: return
        self._fig.clear()
        axes = self._fig.subplots(2, 2)
        titles = [('Атаки по времени', axes[0][0]),
                  ('Типы атак',        axes[0][1]),
                  ('SSH vs FTP',       axes[1][0]),
                  ('Топ 5 IP',         axes[1][1])]
        for title, ax in titles:
            ax.set_facecolor(PANEL)
            for sp in ax.spines.values(): sp.set_edgecolor(BORDER)
            ax.tick_params(colors=DIM, labelsize=8)
            ax.set_title(title, color=SKY, fontsize=9, pad=8)
            ax.text(0.5, 0.5, 'Нет данных', transform=ax.transAxes,
                    ha='center', va='center', color=DIM, fontsize=9)
        self._mpl_canvas.draw()

    def _refresh_charts(self):
        if not HAS_MPL: return
        self._chart_refresh_pending = False
        self._fig.clear()
        axes = self._fig.subplots(2, 2)

        def style_ax(ax, title):
            ax.set_facecolor(PANEL)
            for sp in ax.spines.values(): sp.set_visible(False)
            ax.tick_params(colors=DIM, labelsize=8)
            ax.set_title(title, color=SKY, fontsize=9, pad=8)

        # 1 Атаки по времени
        ax = axes[0][0]
        style_ax(ax, 'Атаки по времени')
        if self._timeline:
            by_min = defaultdict(int)
            for ts, _ in self._timeline:
                by_min[ts.strftime('%H:%M')] += 1
            mins   = sorted(by_min)
            counts = [by_min[m] for m in mins]
            xs = range(len(mins))
            ax.plot(xs, counts, color=RED, linewidth=2,
                    marker='o', markersize=4, zorder=3)
            ax.fill_between(xs, counts, alpha=0.12, color=RED)
            step = max(1, len(mins) // 7)
            ax.set_xticks(range(0, len(mins), step))
            ax.set_xticklabels([mins[i] for i in range(0, len(mins), step)],
                               rotation=30, ha='right', fontsize=7, color=DIM)
            ax.set_yticks(range(0, max(counts) + 2))
            ax.grid(axis='y', color=BORDER, linestyle='--', linewidth=0.5)
        else:
            ax.text(0.5, 0.5, 'Нет данных', transform=ax.transAxes,
                    ha='center', va='center', color=DIM, fontsize=9)

        # 2 Типы атак
        ax = axes[0][1]
        style_ax(ax, 'Типы атак')
        if self._atk_type_cnt:
            palette = [RED, AMBER, BLUE, GREEN, PURP, TEAL, SKY, DIM]
            items   = self._atk_type_cnt.most_common(8)
            types   = [i[0] for i in items]
            counts  = [i[1] for i in items]
            colors  = palette[:len(types)]
            bars = ax.barh(types, counts, color=colors, height=0.55)
            for bar, cnt in zip(bars, counts):
                ax.text(bar.get_width() + 0.05, bar.get_y() + bar.get_height() / 2,
                        str(cnt), va='center', color=TEXT, fontsize=8)
            ax.set_xlim(0, max(counts) * 1.28)
            ax.tick_params(axis='y', colors=TEXT)
            ax.tick_params(axis='x', colors=DIM)
        else:
            ax.text(0.5, 0.5, 'Нет данных', transform=ax.transAxes,
                    ha='center', va='center', color=DIM, fontsize=9)

        # 3 SSH vs FTP
        ax = axes[1][0]
        style_ax(ax, 'SSH vs FTP атаки')
        ssh_c = self._proto_cnt.get('ssh', 0)
        ftp_c = self._proto_cnt.get('ftp', 0)
        other = sum(v for k, v in self._proto_cnt.items() if k not in ('ssh', 'ftp'))
        pie_data = [(ssh_c, f'SSH\n{ssh_c}', TEAL),
                    (ftp_c, f'FTP\n{ftp_c}', RED),
                    (other, f'Другие\n{other}', DIM)]
        pie_data = [(v, l, c) for v, l, c in pie_data if v > 0]
        if pie_data:
            vals   = [x[0] for x in pie_data]
            labels = [x[1] for x in pie_data]
            clrs   = [x[2] for x in pie_data]
            ax.pie(vals, labels=labels, colors=clrs, startangle=90,
                   wedgeprops={'width': 0.55, 'linewidth': 0},
                   textprops={'color': TEXT, 'fontsize': 8})
        else:
            ax.text(0.5, 0.5, 'Нет данных', transform=ax.transAxes,
                    ha='center', va='center', color=DIM, fontsize=9)

        # 4 Топ 5 IP
        ax = axes[1][1]
        style_ax(ax, 'Топ 5 IP (попыток)')
        if self._ip_stats:
            top5 = sorted(self._ip_stats.items(),
                          key=lambda x: x[1]['attempts'], reverse=True)[:5]
            ips    = [x[0] for x in top5]
            totals = [x[1]['attempts'] for x in top5]
            fails  = [x[1]['failed']   for x in top5]
            xs     = range(len(ips))
            ax.barh(xs, totals, color=BLUE,  height=0.55, label='Всего', alpha=0.7)
            ax.barh(xs, fails,  color=RED,   height=0.55, label='Неудачных', alpha=0.9)
            ax.set_yticks(list(xs))
            ax.set_yticklabels(ips, fontsize=8, color=TEXT)
            ax.tick_params(axis='x', colors=DIM)
            ax.legend(fontsize=7, facecolor=PANEL, labelcolor=TEXT,
                      edgecolor=BORDER, framealpha=0.8)
            if totals:
                ax.set_xlim(0, max(totals) * 1.2)
        else:
            ax.text(0.5, 0.5, 'Нет данных', transform=ax.transAxes,
                    ha='center', va='center', color=DIM, fontsize=9)

        self._mpl_canvas.draw()

    def _schedule_chart_refresh(self):
        if not self._chart_refresh_pending:
            self._chart_refresh_pending = True
            self.root.after(2500, self._refresh_charts)

    # Системный лог (вкладка)
    def _build_syslog_tab(self):
        tab = ttk.Frame(self._nb)
        self._nb.add(tab, text='  Системный лог  ')

        top = tk.Frame(tab, bg=PANEL, height=42)
        top.pack(fill='x')
        top.pack_propagate(False)
        tk.Label(top, text='Лог приложения и события безопасности',
                 font=sans(10), bg=PANEL, fg=DIM).pack(side='left', padx=12, pady=10)
        tk.Button(top, text='🗑 Очистить', command=self._clear_syslog,
                  bg=MUTED, fg=DIM, relief='flat', font=sans(9),
                  cursor='hand2').pack(side='right', padx=10, pady=6)

        pane = tk.Frame(tab, bg=BG)
        pane.pack(fill='both', expand=True)

        left = tk.Frame(pane, bg=CARD)
        left.pack(side='left', fill='both', expand=True, padx=(12, 4), pady=10)
        self._panel_title(left, 'АЛЕРТЫ БЕЗОПАСНОСТИ')
        self._alert_box = self._make_textbox(left, {
            'HIGH':   {'foreground': RED},
            'MEDIUM': {'foreground': AMBER},
            'LOW':    {'foreground': GREEN},
            'time':   {'foreground': DIM, 'font': mono(8)},
            'dim':    {'foreground': DIM},
            'bold':   {'font': sans(9, True)},
        })

        right = tk.Frame(pane, bg=CARD)
        right.pack(side='right', fill='both', expand=True, padx=(4, 12), pady=10)
        self._panel_title(right, 'СИСТЕМНЫЙ ЛОГ')
        self._sys_box = self._make_textbox(right, {
            'INFO':    {'foreground': TEXT},
            'WARNING': {'foreground': AMBER},
            'ERROR':   {'foreground': RED},
            'DEBUG':   {'foreground': DIM},
            'time':    {'foreground': DIM, 'font': mono(8)},
        })

    def _clear_syslog(self):
        for box in (self._sys_box, self._alert_box):
            box.config(state='normal')
            box.delete('1.0', 'end')
            box.config(state='disabled')

    # Настройки
    def _build_settings_tab(self):
        tab = ttk.Frame(self._nb)
        self._nb.add(tab, text='  Настройки  ')
        canvas = tk.Canvas(tab, bg=BG, highlightthickness=0)
        vsb = ttk.Scrollbar(tab, orient='vertical', command=canvas.yview)
        canvas.configure(yscrollcommand=vsb.set)
        vsb.pack(side='right', fill='y')
        canvas.pack(side='left', fill='both', expand=True)
        inner  = tk.Frame(canvas, bg=BG)
        win_id = canvas.create_window((0, 0), window=inner, anchor='nw')
        inner.bind('<Configure>', lambda e: canvas.configure(scrollregion=canvas.bbox('all')))
        canvas.bind('<Configure>', lambda e: canvas.itemconfig(win_id, width=e.width))
        self._svar: dict = {}
        self._build_settings_form(inner)

    def _build_settings_form(self, parent):
        try:
            with open('config/settings.yaml', encoding='utf-8') as f:
                cfg = yaml.safe_load(f) or {}
        except FileNotFoundError:
            cfg = {}
        app  = cfg.get('app', {})
        logs = cfg.get('logs', {})
        det  = cfg.get('detection', {}).get('thresholds', {})
        alt  = cfg.get('alerting', {})
        tg   = alt.get('telegram', {})
        sections = [
            ('ПРИЛОЖЕНИЕ', [
                ('app.name',        'Название',       app.get('name', 'Bruteforce Detector')),
                ('app.log_level',   'Уровень лога',   app.get('log_level', 'INFO')),
            ]),
            ('ЛОГ-ФАЙЛЫ', [
                ('logs.ssh', 'SSH лог (CSV)',         logs.get('ssh_log_path', '')),
                ('logs.ftp', 'FTP лог (CSV)',         logs.get('ftp_log_path', '')),
                ('logs.int', 'Интервал проверки (с)', str(logs.get('check_interval', 2))),
            ]),
            ('ПОРОГИ ОБНАРУЖЕНИЯ', [
                ('det.max',  'Макс. неудачных попыток', str(det.get('max_failed_attempts', 10))),
                ('det.win',  'Временное окно (мин)',     str(det.get('time_window_minutes', 5))),
                ('det.usr',  'Мин. уникальных юзеров',  str(det.get('min_unique_usernames', 3))),
                ('det.rate', 'Макс. попыток/сек',        str(det.get('max_attempts_per_seconds', 5))),
            ]),
            ('ОПОВЕЩЕНИЯ', [
                ('alt.cool',  'Cooldown алертов (мин)', str(alt.get('cooldown_minutes', 1))),
                ('tg.token',  'Telegram Bot Token',     tg.get('bot_token', '')),
                ('tg.chat',   'Telegram Chat ID',       str(tg.get('chat_id', ''))),
            ]),
        ]
        for sec_name, fields in sections:
            sec = tk.Frame(parent, bg=CARD)
            sec.pack(fill='x', padx=20, pady=(16, 0))
            tk.Frame(sec, bg=BLUE, height=2).pack(fill='x')
            tk.Label(sec, text=sec_name, font=sans(10, True),
                     bg=CARD, fg=SKY).pack(anchor='w', padx=14, pady=(10, 6))
            for key, label, default in fields:
                row = tk.Frame(sec, bg=CARD)
                row.pack(fill='x', padx=14, pady=(0, 8))
                tk.Label(row, text=label, width=26, anchor='w',
                         font=sans(9), bg=CARD, fg=DIM).pack(side='left')
                var = tk.StringVar(value=default)
                self._svar[key] = var
                tk.Entry(row, textvariable=var, bg=MUTED, fg=TEXT,
                         insertbackground=TEXT, relief='flat',
                         font=mono(9), width=34).pack(side='left', ipady=4, padx=(0, 6))
                if key in ('logs.ssh', 'logs.ftp'):
                    tk.Button(row, text='Обзор…',
                              command=lambda v=var: self._browse(v),
                              bg=BORDER, fg=DIM, relief='flat',
                              font=sans(8), cursor='hand2').pack(side='left')
        btn_row = tk.Frame(parent, bg=BG)
        btn_row.pack(fill='x', padx=20, pady=18)
        tk.Button(btn_row, text='💾  Сохранить настройки',
                  command=self._save_settings, bg=BLUE, fg='white',
                  relief='flat', font=sans(10, True), cursor='hand2',
                  pady=8, padx=22).pack(side='right')

    def _browse(self, var):
        p = filedialog.askopenfilename(
            filetypes=[('CSV', '*.csv'), ('Log', '*.log'), ('All', '*')])
        if p: var.set(p)

    def _save_settings(self):
        try:
            try:
                with open('settings.yaml', encoding='utf-8') as f:
                    cfg = yaml.safe_load(f) or {}
            except FileNotFoundError:
                cfg = {}
            def cast(v):
                try: return int(v)
                except ValueError:
                    try: return float(v)
                    except ValueError: return v
            mapping = {
                'app.name':    ['app', 'name'],
                'app.log_level': ['app', 'log_level'],
                'logs.ssh':    ['logs', 'ssh_log_path'],
                'logs.ftp':    ['logs', 'ftp_log_path'],
                'logs.int':    ['logs', 'check_interval'],
                'det.max':     ['detection', 'thresholds', 'max_failed_attempts'],
                'det.win':     ['detection', 'thresholds', 'time_window_minutes'],
                'det.usr':     ['detection', 'thresholds', 'min_unique_usernames'],
                'det.rate':    ['detection', 'thresholds', 'max_attempts_per_seconds'],
                'alt.cool':    ['alerting', 'cooldown_minutes'],
                'tg.token':    ['alerting', 'telegram', 'bot_token'],
                'tg.chat':     ['alerting', 'telegram', 'chat_id'],
            }
            for key, path in mapping.items():
                if key not in self._svar: continue
                d = cfg
                for part in path[:-1]: d = d.setdefault(part, {})
                d[path[-1]] = cast(self._svar[key].get())
            with open('settings.yaml', 'w', encoding='utf-8') as f:
                yaml.dump(cfg, f, allow_unicode=True, default_flow_style=False)
            messagebox.showinfo('Сохранено',
                'Настройки записаны.\nПерезапустите детектор для применения.')
        except Exception as exc:
            messagebox.showerror('Ошибка', f'Не удалось сохранить:\n{exc}')

    # Статус-бар
    def _build_statusbar(self):
        tk.Frame(self.root, bg=BORDER, height=1).pack(fill='x', side='bottom')
        bar = tk.Frame(self.root, bg=PANEL, height=52)
        bar.pack(fill='x', side='bottom')
        bar.pack_propagate(False)
        self._btn_start = tk.Button(bar, text='▶  СТАРТ', command=self._start,
                                    bg=GREEN, fg='#020a04', relief='flat',
                                    font=sans(10, True), cursor='hand2', padx=22)
        self._btn_start.pack(side='left', padx=(14, 4), pady=10)
        self._btn_stop = tk.Button(bar, text='■  СТОП', command=self._stop,
                                   bg=MUTED, fg=DIM, relief='flat',
                                   font=sans(10, True), cursor='hand2',
                                   padx=22, state='disabled')
        self._btn_stop.pack(side='left', padx=4, pady=10)
        tk.Button(bar, text='🗑  Очистить всё', command=self._clear_all,
                  bg=MUTED, fg=DIM, relief='flat', font=sans(10),
                  cursor='hand2', padx=16).pack(side='left', padx=10, pady=10)
        self._lbl_ts = tk.Label(bar, text='', bg=PANEL, fg=DIM, font=mono(8))
        self._lbl_ts.pack(side='right', padx=14)

    # Пуш-уведы
    def _show_toast(self, attack: dict):
        sev       = attack.get('severity', 'MEDIUM')
        sev_color = SEV_COLOR.get(sev, AMBER)
        atk_type  = attack.get('type', 'UNKNOWN')
        ip        = attack.get('source_ip', attack.get('username', '?'))
        reason    = (attack.get('reason', '') or '')[:62]

        toast = tk.Toplevel(self.root)
        toast.overrideredirect(True)
        toast.attributes('-topmost', True)
        toast.configure(bg=CARD)

        # Позиционирование с учётом стека
        offset_y = 80 + len(self._active_toasts) * 98
        x = self.root.winfo_x() + self.root.winfo_width() - 340
        y = self.root.winfo_y() + offset_y
        toast.geometry(f'320x92+{x}+{y}')

        tk.Frame(toast, bg=sev_color, height=3).pack(fill='x')

        body = tk.Frame(toast, bg=CARD)
        body.pack(fill='both', expand=True)

        row1 = tk.Frame(body, bg=CARD)
        row1.pack(fill='x', padx=10, pady=(6, 1))
        tk.Label(row1, text='⚠', font=sans(11), bg=CARD, fg=sev_color
                 ).pack(side='left')
        tk.Label(row1, text=f'  [{sev}]  {atk_type}',
                 font=sans(10, True), bg=CARD, fg=sev_color
                 ).pack(side='left')
        tk.Button(row1, text='✕',
                  command=lambda t=toast: self._close_toast(t),
                  bg=CARD, fg=DIM, relief='flat', cursor='hand2',
                  font=sans(9)).pack(side='right')

        row2 = tk.Frame(body, bg=CARD)
        row2.pack(fill='x', padx=10, pady=(0, 2))
        tk.Label(row2, text=f'IP: {ip}', font=mono(9), bg=CARD, fg=TEXT
                 ).pack(anchor='w')
        if reason:
            tk.Label(row2, text=reason, font=mono(8), bg=CARD, fg=DIM,
                     wraplength=292, justify='left').pack(anchor='w')

        # Прогресс-бар
        prog_host = tk.Frame(toast, bg=CARD, height=4)
        prog_host.pack(fill='x', side='bottom')
        prog_host.pack_propagate(False)
        prog_bar = tk.Frame(prog_host, bg=sev_color, height=4)
        prog_bar.place(relx=0, rely=0, relwidth=1.0, relheight=1.0)

        self._active_toasts.append(toast)
        DURATION = 5000
        STEPS    = 50

        def tick(n):
            if not toast.winfo_exists(): return
            prog_bar.place_configure(relwidth=n / STEPS)
            if n > 0:
                toast.after(DURATION // STEPS, lambda: tick(n - 1))
            else:
                self._close_toast(toast)

        toast.after(60, lambda: tick(STEPS))

    def _close_toast(self, toast):
        if toast in self._active_toasts:
            self._active_toasts.remove(toast)
        try:   toast.destroy()
        except Exception: pass
        # Перестраиваем позиции оставшихся
        for i, t in enumerate(self._active_toasts):
            try:
                x = self.root.winfo_x() + self.root.winfo_width() - 340
                y = self.root.winfo_y() + 80 + i * 98
                t.geometry(f'320x92+{x}+{y}')
            except Exception: pass

    # Управление детектором
    def _start(self):
        if self._running: return
        try:
            from src.config import config  # noqa
        except ImportError as exc:
            messagebox.showerror('Ошибка импорта',
                f'Модули не найдены:\n{exc}\n\nЗапустите gui.py из корня проекта.')
            return
        self._log_handler = QueueLogHandler(self._q)
        root_log = logging.getLogger()
        root_log.addHandler(self._log_handler)
        root_log.setLevel(logging.INFO)
        self._running = True
        self._set_status(True)
        self._write_syslog('INFO', 'Детектор запущен')
        self._thread = threading.Thread(target=self._detector_loop, daemon=True)
        self._thread.start()

    def _detector_loop(self):
        try:
            from src.config import config
            from src.data.parser import LogParser
            from src.data.collector import LogCollector
            from src.detectors.rule_based import RuleBasedDetector
            from src.alerting.notifier import AlertNotifier
            parser    = LogParser(config)
            collector = LogCollector(config, parser)
            detector  = RuleBasedDetector(config)
            notifier  = GUINotifierProxy(AlertNotifier(config), self._q)
            collector.start_monitoring()
            while self._running:
                try:
                    logs = collector.collect_logs()
                    for log_type, df in (logs or {}).items():
                        if not df.empty:
                            self._q.put({'type': 'rows', 'log_type': log_type, 'df': df.copy()})
                            self._q.put({
                                'type':    'stats',
                                'total':   len(df),
                                'failed':  int(df['is_failed'].sum()) if 'is_failed' in df.columns else 0,
                                'success': int(df['is_success'].sum()) if 'is_success' in df.columns else 0,
                                'ips':     set(df['source_ip'].dropna().tolist()) if 'source_ip' in df.columns else set(),
                                'log_type': log_type,
                                'ip_data': self._extract_ip_data(df),
                            })
                            attacks = detector.detect_bruteforce(df, log_type)
                            if attacks:
                                notifier.notify(attacks)
                except Exception as exc:
                    self._q.put({'type': 'log', 'level': 'ERROR',
                                 'msg': f'Ошибка: {exc}',
                                 'time': datetime.now().strftime('%H:%M:%S')})
                    time.sleep(5)
                time.sleep(config.get('logs.check_interval', 2))
            collector.stop_monitoring()
        except Exception as exc:
            self._q.put({'type': 'log', 'level': 'ERROR',
                         'msg': f'Критическая ошибка: {exc}',
                         'time': datetime.now().strftime('%H:%M:%S')})
            self._running = False
            self.root.after(0, lambda: self._set_status(False))

    def _extract_ip_data(self, df) -> dict:
        result = {}
        if 'source_ip' not in df.columns:
            return result
        for ip, grp in df.groupby('source_ip'):
            result[ip] = {
                'attempts': len(grp),
                'failed':   int(grp['is_failed'].sum()) if 'is_failed' in grp.columns else 0,
                'success':  int(grp['is_success'].sum()) if 'is_success' in grp.columns else 0,
                'proto':    str(grp['protocol'].mode()[0])
                            if 'protocol' in grp.columns and not grp['protocol'].isna().all()
                            else '—',
            }
        return result

    def _stop(self):
        self._running = False
        if self._log_handler:
            logging.getLogger().removeHandler(self._log_handler)
        self._set_status(False)
        self._write_syslog('INFO', 'Детектор остановлен')

    def _set_status(self, running: bool):
        if running:
            self._lbl_status.config(text='● RUNNING', fg=GREEN)
            self._btn_start.config(state='disabled', bg=MUTED, fg=DIM)
            self._btn_stop.config(state='normal', bg=RED, fg='white')
        else:
            self._lbl_status.config(text='● STOPPED', fg=DIM)
            self._btn_start.config(state='normal', bg=GREEN, fg='#020a04')
            self._btn_stop.config(state='disabled', bg=MUTED, fg=DIM)

    # Обработка очереди
    def _poll_queue(self):
        try:
            while True:
                msg = self._q.get_nowait()
                t = msg.get('type')
                if   t == 'log':    self._handle_log(msg)
                elif t == 'attack': self._handle_attack(msg)
                elif t == 'rows':   self._handle_rows(msg)
                elif t == 'stats':  self._handle_stats(msg)
        except queue.Empty:
            pass
        self.root.after(120, self._poll_queue)

    def _handle_log(self, msg):
        self._write_syslog(msg.get('level', 'INFO'), msg.get('msg', ''),
                           msg.get('time', ''))

    def _write_syslog(self, level, text, ts=''):
        ts = ts or datetime.now().strftime('%H:%M:%S')
        box = self._sys_box
        box.config(state='normal')
        box.insert('end', f'[{ts}] ', 'time')
        box.insert('end', text + '\n', level)
        box.see('end')
        box.config(state='disabled')
        self._lbl_ts.config(text=f'Обновлено: {ts}')

    def _handle_attack(self, msg):
        a   = msg['data']
        ts  = msg['time']
        sev = a.get('severity', 'MEDIUM')
        ip  = a.get('source_ip', a.get('username', '—'))

        # Алерт-бокс
        box = self._alert_box
        box.config(state='normal')
        box.insert('end', f'[{ts}]  ', 'time')
        box.insert('end', f'[{sev}]', sev)
        box.insert('end', f'  {a["type"]}  ', 'bold')
        box.insert('end', ip + '\n', sev)
        box.insert('end', f'  └─ {a.get("reason", "")}\n\n', 'dim')
        box.see('end')
        box.config(state='disabled')

        # Attacks tab
        vals = (ts, sev, a.get('type', ''), ip,
                a.get('username', '—'), a.get('reason', ''),
                a.get('failed_attempts', '—'))
        self._attack_rows.append((vals, sev, a))

        # Пересортируем и перерисуем
        col_idx = self._atk_cols.index(self._sort_col)
        def key(row):
            v = row[0][col_idx]
            try:    return (0, int(v))
            except: return (1, str(v).lower())
        self._attack_rows.sort(key=key, reverse=self._sort_rev)
        self._rerender_attacks()

        # Счётчики
        self._stats['attacks'] += 1
        if a.get('log_type', '').lower() == 'ssh':
            self._ssh_attacks += 1
        elif a.get('log_type', '').lower() == 'ftp':
            self._ftp_attacks += 1
        if datetime.now().date() == date.today():
            self._today_attacks += 1
        self._atk_type_cnt[a.get('type', 'unknown')] += 1
        self._proto_cnt[a.get('log_type', 'unknown').lower()] += 1
        self._timeline.append((datetime.now(), sev))

        self._refresh_cards()
        self._lbl_atk_count.config(
            text=f'Обнаружено атак: {self._stats["attacks"]}', fg=RED)

        # Пуш-увед
        self._show_toast(a)

        # Графики
        self._schedule_chart_refresh()

    def _handle_rows(self, msg):
        df = msg['df']
        for _, row in df.iterrows():
            status = str(row.get('status', ''))
            if any(x in status for x in ('FAIL', 'ERROR', 'DENI')):
                tag = 'FAIL'
            elif any(x in status for x in ('SUCCESS', 'OK')):
                tag = 'SUCCESS'
            else:
                tag = 'even'
            vals = (
                str(row.get('timestamp', ''))[:19],
                str(row.get('source_ip', '')),
                str(row.get('username', '')),
                str(row.get('protocol', '')),
                status,
                str(row.get('details', ''))[:90],
            )
            self._log_rows.append((vals, tag))
            flt = self._filter_var.get().lower()
            if not flt or any(flt in str(v).lower() for v in vals):
                self._log_tree.insert('', 'end', values=vals, tags=(tag,))
        if self._autoscroll_var.get():
            ch = self._log_tree.get_children()
            if ch: self._log_tree.see(ch[-1])

    def _handle_stats(self, msg):
        self._stats['total']   += msg.get('total',   0)
        self._stats['failed']  += msg.get('failed',  0)
        self._stats['success'] += msg.get('success', 0)
        self._stats['ips'].update(msg.get('ips', set()))
        for ip, data in msg.get('ip_data', {}).items():
            if ip not in self._ip_stats:
                self._ip_stats[ip] = {'attempts': 0, 'failed': 0, 'success': 0, 'proto': '—'}
            self._ip_stats[ip]['attempts'] += data['attempts']
            self._ip_stats[ip]['failed']   += data['failed']
            self._ip_stats[ip]['success']  += data['success']
            self._ip_stats[ip]['proto']     = data['proto']
        self._refresh_cards()
        self._refresh_ip_table()

    # Вспомогательные
    def _refresh_cards(self):
        self._sc_total.config(text=str(self._stats['total']))
        self._sc_failed.config(text=str(self._stats['failed']))
        self._sc_success.config(text=str(self._stats['success']))
        self._sc_ips.config(text=str(len(self._stats['ips'])))
        self._sc_attacks.config(text=str(self._stats['attacks']))
        self._sc_today.config(text=str(self._today_attacks))
        self._sc_ssh.config(text=str(self._ssh_attacks))
        self._sc_ftp.config(text=str(self._ftp_attacks))

    def _refresh_ip_table(self):
        self._ip_tree.delete(*self._ip_tree.get_children())
        top20 = sorted(self._ip_stats.items(),
                       key=lambda x: x[1]['attempts'], reverse=True)[:20]
        for ip, d in top20:
            tag = 'hot' if d['failed'] > 10 else 'warm' if d['failed'] > 3 else 'cool'
            self._ip_tree.insert('', 'end',
                values=(ip, d['attempts'], d['failed'], d['success'], d['proto']),
                tags=(tag,))

    def _apply_filter(self, *_):
        term = self._filter_var.get().lower()
        self._log_tree.delete(*self._log_tree.get_children())
        for vals, tag in self._log_rows:
            if not term or any(term in str(v).lower() for v in vals):
                self._log_tree.insert('', 'end', values=vals, tags=(tag,))

    def _clear_all(self):
        for box in (self._sys_box, self._alert_box):
            box.config(state='normal')
            box.delete('1.0', 'end')
            box.config(state='disabled')
        for tree in (self._log_tree, self._atk_tree, self._ip_tree):
            tree.delete(*tree.get_children())
        self._stats = {'total': 0, 'failed': 0, 'success': 0,
                       'ips': set(), 'attacks': 0}
        self._today_attacks = self._ssh_attacks = self._ftp_attacks = 0
        self._attack_rows.clear()
        self._log_rows.clear()
        self._ip_stats.clear()
        self._atk_type_cnt.clear()
        self._proto_cnt.clear()
        self._timeline.clear()
        self._refresh_cards()
        self._lbl_atk_count.config(text='Атак не обнаружено', fg=DIM)
        if HAS_MPL: self._draw_empty_charts()

    # Старт приложения
    def run(self):
        self.root.protocol('WM_DELETE_WINDOW', self._on_close)
        self.root.mainloop()

    def _on_close(self):
        self._running = False
        self.root.destroy()


if __name__ == '__main__':
    app = BruteforceGUI()
    app.run()
