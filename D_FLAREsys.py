# dflare_sys.py
"""
D-FLARE SYS — 多層集成式防火牆威脅分級系統（Cisco ASA 5506-X 專用）
支援流水號（batch_id）與 append 機制
"""

import os
import sys
import csv
import json
import time
import math  # <--- 新增
import ipaddress
import pandas as pd
from tqdm import tqdm
from colorama import init, Fore, Style

# 繪圖
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec

# 百分比四捨五入（兩位小數）
from decimal import Decimal, ROUND_HALF_UP

def ceil_to_step(max_val, step=500, minimum=500):
    """
    將 max_val 向上進位到指定 step 的倍數（預設 500），最小上限至少為 minimum。
    例如：3765->4000、1234->1500、0 或負數 -> 500
    """
    try:
        m = float(max_val)
    except Exception:
        return minimum
    if m <= 0:
        return minimum
    return int(np.ceil(m / step) * step)

def format_pct2(pct_value: float) -> str:
    """
    將百分比四捨五入到小數點後兩位，回傳 'xx.xx%'.
    使用 ROUND_HALF_UP（一般四捨五入）。
    """
    d = Decimal(str(pct_value)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    # 強制兩位小數格式
    return f"{d:.2f}%"

def draw_pie_with_side_legend(values, labels, colors, output_path,
                              title="",
                              startangle=90, edgecolor="#FFFFFF",
                              show_total=True, total_label="合計", dpi=150,
                              decimals=2):
    """
    左邊畫圓餅；右邊用表格顯示類別與百分比（四捨五入到小數點後兩位）。
    """
    vals = np.array(values, dtype=float)
    total = vals.sum()
    if total <= 0:
        plt.figure(figsize=(8,5), dpi=dpi)
        plt.text(0.5, 0.5, '無資料', fontsize=18, ha='center', va='center')
        plt.axis('off')
        plt.tight_layout()
        plt.savefig(output_path, bbox_inches='tight', dpi=dpi)
        plt.close()
        return

    fig = plt.figure(figsize=(8.5, 5.2), dpi=dpi)
    gs = gridspec.GridSpec(1, 2, width_ratios=[2, 1], wspace=0.05)
    ax_pie = fig.add_subplot(gs[0, 0])
    ax_leg = fig.add_subplot(gs[0, 1])

    # 左：圓餅（扇形上不印文字，避免重疊）
    ax_pie.pie(vals, labels=None, colors=colors, startangle=startangle,
               wedgeprops=dict(edgecolor=edgecolor, linewidth=2))
    ax_pie.set_aspect('equal')
    if title:
        ax_pie.set_title(title, fontsize=18, pad=16)

    # 右：表格 + 兩位小數百分比
    ax_leg.axis('off'); ax_leg.set_xlim(0,1); ax_leg.set_ylim(0,1)
    pct = vals / total * 100.0

    ax_leg.text(0.05, 0.95, "區域", fontsize=12, weight='bold', va='center')
    ax_leg.text(0.78, 0.95, "占比", fontsize=12, weight='bold', va='center')
    ax_leg.hlines(0.90, 0.03, 0.97, colors="#bdbdbd", linewidth=1)

    n = len(labels); top = 0.85; row_h = 0.12 if n <= 4 else 0.09
    for i, (lab, p, c) in enumerate(zip(labels, pct, colors)):
        y = top - i*row_h
        ax_leg.scatter(0.07, y, s=220, color=c)
        ax_leg.text(0.12, y, str(lab), fontsize=12, va='center')
        ax_leg.text(0.95, y, format_pct2(p), fontsize=12, va='center', ha='right')

    if show_total:
        ax_leg.hlines(top - n*row_h - 0.03, 0.03, 0.97, colors="#bdbdbd", linewidth=1)
        ax_leg.text(0.12, top - n*row_h - 0.10, total_label, fontsize=12, va='center')
        ax_leg.text(0.95, top - n*row_h - 0.10, "100.00%", fontsize=12, va='center', ha='right')

    fig.patch.set_facecolor("#fcfcfc")
    plt.tight_layout()
    plt.savefig(output_path, bbox_inches='tight', dpi=dpi)
    plt.close()

# ====== 圖表：動態 Y 軸工具函式 ======
def dynamic_ylim_from_values(vals):
    """
    以 1-2-5-10 的 nice number 規則自動計算 Y 軸上限，確保小量資料不會被壓扁，
    也不會硬生生跳到 500。
    """
    m = int(max(vals)) if vals else 0
    if m <= 0:
        return 8  # 最低高度，避免只有 0 時圖太扁

    target = m * 1.15  # 15% headroom
    exp = math.floor(math.log10(target))
    base = target / (10 ** exp)

    if base <= 1:
        nice = 1
    elif base <= 2:
        nice = 2
    elif base <= 5:
        nice = 5
    else:
        nice = 10

    return int(nice * (10 ** exp))
# ====== 初始化 colorama ======

init(autoreset=True)

# ====== ACL deny 覆寫與行為分級（強化） ======
ATTEMPT_DENY_IDS = {"710003", "106023", "106021", "106016", "106015", "106014", "106006"}

def _normalize_columns(df: pd.DataFrame) -> pd.DataFrame:
    """
    對齊/補齊常用欄位
    """
    df = df.copy()
    need_cols = [
        "event_id", "SyslogID", "Description", "raw_log", "Severity", "Datetime",
        "DestinationPort", "DestinationIP", "deny_cnt_60", "deny_u_dport_60",
        "deny_u_dip_60", "crlevel", "is_attack", "attack_type",
        "blocked", "src_if", "dst_if", "direction", "SourceIP"
    ]
    for c in need_cols:
        if c not in df.columns:
            df[c] = ""

    # 用 SyslogID 補 event_id（僅補空/NaN）
    eid_empty = df["event_id"].astype(str).str.strip().eq("") | df["event_id"].isna()
    df.loc[eid_empty, "event_id"] = df.loc[eid_empty, "SyslogID"].astype(str)

    # 型別
    df["is_attack"] = pd.to_numeric(df["is_attack"], errors="coerce").fillna(0).astype(int)
    df["blocked"] = pd.to_numeric(df["blocked"], errors="coerce").fillna(0).astype(int)
    return df

# ---------- 介面/方向抽取 ----------
def parse_interfaces_and_direction(df: pd.DataFrame) -> pd.DataFrame:
    """
    從 Description/raw_log 推斷 dst_if（to outside:IP/port 或 on interface inside）
    並推估 direction（inside/outside -> dst_if）
    """
    import re
    df = _normalize_columns(df)
    text = (df["Description"].astype(str) + " " + df["raw_log"].astype(str))

    # e.g. "to outside:120.125.85.60/443"
    m_to = text.str.extract(r"\bto\s+([A-Za-z0-9_-]+):\d+\.\d+\.\d+\.\d+/\d+", expand=True)
    # e.g. "on interface inside"
    m_on = text.str.extract(r"on\s+interface\s+([A-Za-z0-9_-]+)", expand=True)

    df.loc[m_to[0].notna(), "dst_if"] = m_to[0]
    df.loc[m_on[0].notna() & df["dst_if"].eq(""), "dst_if"] = m_on[0]

    def infer_dir(row):
        if row["dst_if"]:
            txt = f"{row['Description']} {row['raw_log']}".lower()
            # 若描述內含 outside 或來源為公網，視為 outside 出發
            try:
                ip = ipaddress.ip_address(str(row["SourceIP"]))
                is_private = ip.is_private
            except Exception:
                is_private = False
            src_if = "outside" if (("outside" in txt) or (not is_private)) else "inside"
            return f"{src_if}->{row['dst_if']}"
        return ""
    df["direction"] = df.apply(infer_dir, axis=1)
    return df

# ---------- 語意偵測 ----------
def semantic_attack_labels(df: pd.DataFrame) -> pd.DataFrame:
    df = _normalize_columns(df)

    # event_id family
    eid = df["event_id"].astype(str).str.extract(r"(\d+)")[0].fillna("")
    mask_acl = eid.isin(ATTEMPT_DENY_IDS)

    low = (df["Description"].astype(str) + " " + df["raw_log"].astype(str)).str.lower()
    m_spoof = low.str.contains("ip spoof", na=False)
    m_no_conn = low.str.contains("no connection", na=False)
    m_deny = (
        low.str.contains(r"asa-\d+-710003", na=False) |
        low.str.contains("access denied", na=False)   |
        low.str.contains(r"\bdeny\b", na=False)       |
        low.str.contains(r"\bdenied\b", na=False)
    )

    mask_attack = mask_acl | m_deny | m_spoof | m_no_conn
    df.loc[mask_attack, "is_attack"] = 1
    df.loc[mask_attack, "blocked"] = 1

    df.loc[m_spoof, "attack_type"] = df["attack_type"].where(df["attack_type"].ne(""), "ip_spoof")
    df.loc[m_no_conn, "attack_type"] = df["attack_type"].where(df["attack_type"].ne(""), "out_of_state_tcp")
    df.loc[mask_acl | m_deny, "attack_type"] = df["attack_type"].where(df["attack_type"].ne(""), "deny_by_acl")
    return df

def add_acl_deny_window_stats(df: pd.DataFrame, window_sec: int = 60) -> pd.DataFrame:
    """
    根據 event_id，計算每筆在 window_sec 秒內的 deny 次數、唯一目的埠、唯一目的IP。
    假設 'Datetime' 欄位為時間戳字串。
    """
    import numpy as np

    df = _normalize_columns(df)
    if "Datetime" not in df.columns or "event_id" not in df.columns:
        df["deny_cnt_60"] = 0
        df["deny_u_dport_60"] = 0
        df["deny_u_dip_60"] = 0
        return df

    # 僅對關心的事件做統計
    mask = df["event_id"].astype(str).isin(ATTEMPT_DENY_IDS)
    if not mask.any():
        df["deny_cnt_60"] = 0
        df["deny_u_dport_60"] = 0
        df["deny_u_dip_60"] = 0
        return df

    # 轉時間、排序
    d = df.copy()
    d["Datetime"] = pd.to_datetime(d["Datetime"], errors="coerce")
    d = d.sort_values("Datetime")

    d["deny_cnt_60"] = 0
    d["deny_u_dport_60"] = 0
    d["deny_u_dip_60"] = 0

    idxs = d[mask].index
    for idx in idxs:
        t = d.at[idx, "Datetime"]
        if pd.isna(t):
            continue
        eid = str(d.at[idx, "event_id"])
        window_start = t - pd.Timedelta(seconds=window_sec)
        win = d[
            (d["Datetime"] >= window_start) &
            (d["Datetime"] <= t) &
            (d["event_id"].astype(str) == eid)
        ]
        d.at[idx, "deny_cnt_60"] = len(win)
        d.at[idx, "deny_u_dport_60"] = win["DestinationPort"].nunique() if "DestinationPort" in win.columns else 0
        d.at[idx, "deny_u_dip_60"] = win["DestinationIP"].nunique() if "DestinationIP" in win.columns else 0

    cols = ["deny_cnt_60", "deny_u_dport_60", "deny_u_dip_60"]
    for c in cols:
        df[c] = d[c]
    return df

def overlay_acl_deny_rules(df: pd.DataFrame) -> pd.DataFrame:
    """快速覆寫：所有 ACL-deny 族群 → 一律標為攻擊嘗試（已阻擋）。"""
    df = _normalize_columns(df.copy())
    mask = df["event_id"].astype(str).str.extract(r"(\d+)")[0].isin(ATTEMPT_DENY_IDS)
    if "is_attack" not in df.columns:
        df["is_attack"] = 0
    if "attack_type" not in df.columns:
        df["attack_type"] = ""
    df.loc[mask, "is_attack"] = 1
    df.loc[mask, "attack_type"] = df["attack_type"].where(~mask, "deny_by_acl")
    df.loc[mask, "blocked"] = 1
    return df

def overlay_acl_deny_scoring(df: pd.DataFrame) -> pd.DataFrame:
    """依 60 秒內被拒次數/唯一埠/唯一目的IP 決定 crlevel：1(高), 2(中), 3(低)。"""
    import numpy as np

    df = _normalize_columns(df.copy())
    mask = df["event_id"].astype(str).isin(ATTEMPT_DENY_IDS)

    if "deny_cnt_60" not in df.columns:
        df.loc[mask, "crlevel"] = 2
        return df

    z = np.zeros(len(df))
    hi = mask & (
        (pd.to_numeric(df["deny_cnt_60"], errors="coerce").fillna(0) >= 10) |
        (pd.to_numeric(df.get("deny_u_dport_60", pd.Series(z)), errors="coerce").fillna(0) >= 5) |
        (pd.to_numeric(df.get("deny_u_dip_60",   pd.Series(z)), errors="coerce").fillna(0) >= 3)
    )
    med = mask & (~hi) & (
        (pd.to_numeric(df["deny_cnt_60"], errors="coerce").fillna(0).between(4, 9, inclusive="both")) |
        (pd.to_numeric(df.get("deny_u_dport_60", pd.Series(z)), errors="coerce").fillna(0).between(2, 4, inclusive="both"))
    )
    low = mask & (~hi) & (~med)

    df.loc[hi,  "crlevel"] = 1
    df.loc[med, "crlevel"] = 2
    df.loc[low, "crlevel"] = 3
    return df

def apply_acl_deny_overlay(df_pred: pd.DataFrame, window_sec: int = 60) -> pd.DataFrame:
    """加視窗特徵 → 一律標攻擊 → 行為分級。"""
    df_pred = add_acl_deny_window_stats(df_pred, window_sec=window_sec)
    df_pred = overlay_acl_deny_rules(df_pred)
    df_pred = overlay_acl_deny_scoring(df_pred)
    return df_pred

# ====== A+B 規則設定 ======
DFLARE_A_STRICT_CODES = {"710003", "106023", "106021", "106016", "106015", "106014", "106006"}
DFLARE_A_TEXT_PATTERNS = [
    r"asa-\d+-710003",
    r"\baccess denied\b",
    r"\bdeny\b",
    r"\bdenied\b",
    r"\bno connection\b",
    r"\breverse path check\b"
]

DFLARE_B_CTX = {
    "window_sec": 60,
    "deny_cnt_hi": 6,
    "unique_dport_hi": 3,
    "unique_dip_hi": 2,
    "severity_gate": 4,
    "inside_if_markers": [" on interface inside", " on interface dmz"],
}

def _safe_append_tag(series: pd.Series, tag: str) -> pd.Series:
    """把 attack_type 加上新標籤，不重複、不覆蓋既有內容。"""
    s = series.fillna("").astype(str)
    def _merge(v):
        if not v or v.strip() == "":
            return tag
        parts = [p for p in v.split("|") if p]
        if tag not in parts:
            parts.append(tag)
        return "|".join(parts)
    return s.apply(_merge)

def apply_acl_strict_and_context(df: pd.DataFrame, *, window_sec: int = None) -> pd.DataFrame:
    """
    A（嚴格）：代碼/文字命中 → is_attack=1, tag=A_strict
    B（情境）：視窗門檻或文字線索/inside 提示 → is_attack=1, tag=B_context
    """
    df = _normalize_columns(df.copy())

    eid_num = df["event_id"].astype(str).str.extract(r"(\d+)")[0].fillna("")
    txt = (df.get("Description", "").astype(str) + " " + df.get("raw_log", "").astype(str)).str.lower()

    a_code = eid_num.isin(DFLARE_A_STRICT_CODES)
    import re
    a_text = pd.Series(False, index=df.index)
    for pat in DFLARE_A_TEXT_PATTERNS:
        a_text = a_text | txt.str.contains(pat, na=False, regex=True)

    a_mask = a_code | a_text
    if "is_attack" not in df.columns:
        df["is_attack"] = 0
    if "attack_type" not in df.columns:
        df["attack_type"] = ""

    df.loc[a_mask, "is_attack"] = 1
    df.loc[a_mask, "attack_type"] = _safe_append_tag(df.loc[a_mask, "attack_type"], "A_strict")

    _w = window_sec or DFLARE_B_CTX["window_sec"]
    df = add_acl_deny_window_stats(df, window_sec=_w)

    cnt = pd.to_numeric(df.get("deny_cnt_60", 0), errors="coerce").fillna(0)
    u_dport = pd.to_numeric(df.get("deny_u_dport_60", 0), errors="coerce").fillna(0)
    u_dip = pd.to_numeric(df.get("deny_u_dip_60", 0), errors="coerce").fillna(0)

    b_cnt = cnt >= DFLARE_B_CTX["deny_cnt_hi"]
    b_dport = u_dport >= DFLARE_B_CTX["unique_dport_hi"]
    b_dip = u_dip >= DFLARE_B_CTX["unique_dip_hi"]

    has_no_conn = txt.str.contains(r"\bno connection\b", na=False)
    has_rpf = txt.str.contains(r"\breverse path check\b", na=False)
    inside_hint = pd.Series(False, index=df.index)
    for m in DFLARE_B_CTX["inside_if_markers"]:
        inside_hint = inside_hint | txt.str.contains(re.escape(m), na=False)

    b_mask = b_cnt | b_dport | b_dip | has_no_conn | has_rpf | inside_hint
    b_only = b_mask & (~a_mask)

    df.loc[b_only, "is_attack"] = 1
    df.loc[b_only, "attack_type"] = _safe_append_tag(df.loc[b_only, "attack_type"], "B_context")
    return df

def force_mark_acl_deny_anywhere(df: pd.DataFrame) -> pd.DataFrame:
    """
    極限保險：偵測到 710003 或 deny 文字，無論其他結果，is_attack=1。
    """
    df = _normalize_columns(df.copy())

    sid = df.get("SyslogID", "").astype(str)
    eid = df.get("event_id", "").astype(str)

    sid_num = sid.str.extract(r"(\d+)")[0].fillna("")
    eid_num = eid.str.extract(r"(\d+)")[0].fillna("")
    m_id = sid_num.eq("710003") | eid_num.eq("710003")

    text = (df.get("Description", "").astype(str) + " " + df.get("raw_log", "").astype(str)).str.lower()
    m_txt = (
        text.str.contains(r"asa-\d+-710003", na=False) |
        text.str.contains("access denied", na=False)   |
        text.str.contains(r"\bdeny\b", na=False)       |
        text.str.contains(r"\bdenied\b", na=False)
    )

    mask = m_id | m_txt
    df.loc[mask, "is_attack"] = 1
    # 若已有 attack_type，不覆蓋；否則標上 final tag
    df.loc[mask, "attack_type"] = df["attack_type"].where(~mask | df["attack_type"].astype(str).ne(""),
                                                          "deny_by_acl_final")
    df.loc[mask, "blocked"] = 1
    return df

# ---------- 白名單 ----------
def load_whitelist(path: str):
    ip_set, net_list = set(), []
    if not path or not os.path.exists(path): return ip_set, net_list
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            s = line.strip()
            if not s or s.startswith("#"): continue
            try:
                if "/" in s: net_list.append(ipaddress.ip_network(s, strict=False))
                else: ip_set.add(ipaddress.ip_address(s))
            except Exception:
                continue
    return ip_set, net_list

def ip_in_whitelist(ip_str, ip_set, net_list) -> bool:
    try:
        ip = ipaddress.ip_address(str(ip_str))
    except Exception:
        return False
    if ip in ip_set: return True
    return any(ip in n for n in net_list)

def apply_whitelist(df: pd.DataFrame, ip_set, net_list) -> pd.DataFrame:
    df = _normalize_columns(df)
    wl = df["SourceIP"].apply(lambda x: ip_in_whitelist(x, ip_set, net_list)) | \
         df["DestinationIP"].apply(lambda x: ip_in_whitelist(x, ip_set, net_list))
    df.loc[wl, "is_attack"] = 0
    df.loc[wl, "attack_type"] = "whitelisted"
    df.loc[wl, "blocked"] = 0
    return df

def _redraw_binary_charts_from_df(df: pd.DataFrame, output_pie: str, output_bar: str):
    """把覆寫後的二元結果重新畫圖，確保圖表與 CSV 一致。"""
    import matplotlib.pyplot as plt
    from matplotlib.font_manager import FontProperties
    from matplotlib.ticker import MaxNLocator, FuncFormatter

    if os.name == "nt":
        font_path = "C:/Windows/Fonts/msjh.ttc"
    elif os.path.exists("/System/Library/Fonts/PingFang.ttc"):
        font_path = "/System/Library/Fonts/PingFang.ttc"
    else:
        font_path = "/usr/share/fonts/truetype/arphic/uming.ttc"
    font_name = FontProperties(fname=font_path).get_name()
    plt.rcParams['font.family'] = font_name
    plt.rcParams['axes.unicode_minus'] = False
    plt.rcParams['figure.facecolor'] = "#fcfcfc"

    is_attack_dist = df['is_attack'].value_counts().sort_index().reindex([0, 1], fill_value=0)
    labels_attack = ['正常流量', '攻擊流量']
    pie_base_colors = ["#04ff11", "#FF0000"]

    # 圓餅
    values = [int(is_attack_dist.get(0, 0)), int(is_attack_dist.get(1, 0))]
    draw_pie_with_side_legend(
        values=values,
        labels=labels_attack,
        colors=pie_base_colors,
        output_path=output_pie,
        title="攻擊與正常流量比例（二元）",
        decimals=2
    )

    # 長條（動態 Y 軸 + 千分位 + 置中數字）
    plt.figure(figsize=(7, 5))
    ax = plt.gca()
    vals = [int(is_attack_dist.loc[0]), int(is_attack_dist.loc[1])]
    y_top = dynamic_ylim_from_values(vals)

    plt.bar(labels_attack, vals, color=pie_base_colors, edgecolor="#333", width=0.6)
    ax.set_ylim(0, y_top)
    ax.yaxis.set_major_locator(MaxNLocator(integer=True))
    ax.yaxis.set_major_formatter(FuncFormatter(lambda x, _: f"{int(x):,}"))
    ax.yaxis.grid(True, linewidth=1, alpha=0.25)
    for spine in ['top','right']:
        ax.spines[spine].set_visible(False)
    for idx, v in enumerate(vals):
        y_lab = min(v + y_top * 0.05, y_top * 0.98)
        ax.text(idx, y_lab, f"{int(v):,}", ha='center', va='bottom', fontsize=13)

    ax.set_xlabel('流量類型', fontsize=15, labelpad=10)
    ax.set_ylabel('數量（筆）', fontsize=15, labelpad=10)
    ax.set_title('攻擊與正常流量數量分布（二元）', fontsize=18, pad=18)
    plt.tight_layout()
    plt.savefig(output_bar, bbox_inches='tight')
    plt.close()

# ---------- 告警彙整 ----------
def build_alerts(df: pd.DataFrame, out_json: str):
    df = _normalize_columns(df)
    out = {}
    vc = df.loc[df["is_attack"]==1, "crlevel"].value_counts(dropna=False).to_dict()
    out["attack_crlevel_distribution"] = {str(k): int(v) for k,v in vc.items()}
    vt = df.loc[df["is_attack"]==1, "attack_type"].value_counts().to_dict()
    out["attack_type_distribution"] = {str(k): int(v) for k,v in vt.items()}
    vd = df.loc[df["is_attack"]==1, "direction"].value_counts().head(10).to_dict()
    out["top_directions"] = vd
    # 欄位兼容
    src_col = "SourceIP" if "SourceIP" in df.columns else ("src_ip" if "src_ip" in df.columns else None)
    if src_col:
        vs = df.loc[df["is_attack"]==1, src_col].value_counts().head(10).to_dict()
        out["top_source_ip"] = {str(k): int(v) for k,v in vs.items()}
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)

# ==== 取得新的 batch_id ====
def get_next_batch_id(all_results_path):
    if not os.path.exists(all_results_path):
        return 1
    try:
        df = pd.read_csv(all_results_path)
        if "batch_id" in df.columns and not df.empty:
            return int(df["batch_id"].max()) + 1
        else:
            return 1
    except Exception:
        return 1

# =============== STEP1 ===============
def step1_process_logs(raw_log_path, step1_out_path, unique_out_json, batch_id, show_progress=True):
    import gzip, io
    import chardet

    STANDARD_COLUMNS = [
        "batch_id", "Datetime", "SyslogID", "Severity", "SourceIP", "SourcePort",
        "DestinationIP", "DestinationPort", "Duration", "Bytes",
        "Protocol", "Action", "Description", "raw_log"
    ]
    unique_vals = {col: set() for col in STANDARD_COLUMNS}
    CHUNK_SIZE = 50000

    def detect_encoding_safely(file_path, sample_bytes=200_000):
        try:
            if str(file_path).lower().endswith(".gz"):
                with gzip.open(file_path, "rb") as f:
                    raw = f.read(sample_bytes)
            else:
                with open(file_path, "rb") as f:
                    raw = f.read(sample_bytes)
            enc = chardet.detect(raw).get("encoding") or "utf-8"
            return enc
        except Exception:
            return "utf-8"

    def count_lines_binary(file_path):
        bufsize = 1024 * 1024
        total = 0
        if str(file_path).lower().endswith(".gz"):
            with gzip.open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(bufsize), b""): total += chunk.count(b"\n")
        else:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(bufsize), b""): total += chunk.count(b"\n")
        return max(total, 1)

    def open_text_stream(file_path, encoding):
        if str(file_path).lower().endswith(".gz"):
            g = gzip.open(file_path, "rb")
            return io.TextIOWrapper(g, encoding=encoding, errors="replace", newline="")
        else:
            return open(file_path, "r", encoding=encoding, errors="replace", newline="")

    print(f"{Fore.CYAN}{Style.BRIGHT}STEP1：開始資料清洗與唯一值統計")
    encoding = detect_encoding_safely(raw_log_path)
    total_lines = count_lines_binary(raw_log_path)

    processed_count = 0
    f = open_text_stream(raw_log_path, encoding)
    try:
        with f as tf, open(step1_out_path, "w", newline='', encoding="utf-8") as out_f:
            reader = csv.DictReader(tf)
            writer = csv.DictWriter(out_f, fieldnames=STANDARD_COLUMNS)
            writer.writeheader()
            pbar_total = max(total_lines - 1, 0)
            pbar = tqdm(reader, total=pbar_total, desc=f"{Fore.CYAN}清洗進度", disable=not show_progress)

            for i, row in enumerate(pbar):
                if i < 2:
                    print("[STEP1] DEBUG row keys:", list(row.keys()))
                    print("[STEP1] DEBUG row content:", row)
                record = {col: row.get(col, "") for col in STANDARD_COLUMNS if col != "batch_id" and col != "raw_log"}
                record["batch_id"] = batch_id
                record["raw_log"] = json.dumps(row, ensure_ascii=False)

                for col in STANDARD_COLUMNS:
                    if col not in record:
                        record[col] = "unknown"
                    unique_vals[col].add(record[col])

                writer.writerow(record)
                processed_count += 1
                if (i + 1) % 10000 == 0:
                    pbar.set_postfix_str(
                        f"{Fore.YELLOW}已處理 {i + 1} 筆，唯一值累計：{ {k: len(v) for k, v in unique_vals.items()} }"
                    )
                if (i + 1) % CHUNK_SIZE == 0:
                    out_f.flush()
        print(f"{Fore.GREEN}{Style.BRIGHT}STEP1 結束，共處理 {processed_count} 筆資料。")
    finally:
        try: f.close()
        except Exception: pass

    unique_json = {k: sorted([str(x) for x in v]) for k, v in unique_vals.items()}
    with open(unique_out_json, "w", encoding="utf-8") as fjson:
        json.dump(unique_json, fjson, ensure_ascii=False, indent=4)
    print(f"{Fore.GREEN}{Style.BRIGHT}STEP1 完成：已輸出 {step1_out_path} 及 {unique_out_json}")

# =============== STEP2 ===============
def step2_preprocess_data(step1_out_path, step2_out_path, unique_json, show_progress=True):
    with open(unique_json, "r", encoding="utf-8") as f:
        unique_vals = json.load(f)
    CATEGORICAL_MAPPINGS = {
        "Protocol": {
            "http": 1, "https": 2, "icmp": 3, "tcp": 4, "udp": 5,
            "scan": 6, "flood": 7, "other": 8, "unknown": 0, "nan": -1
        },
        "Action": {
            "built": 1, "teardown": 2, "deny": 3, "drop": 4,
            "login": 5, "other": 6, "unknown": 0, "nan": -1
        }
    }
    print(f"{Fore.CYAN}{Style.BRIGHT}STEP2：開始欄位標準化與映射")
    CHUNK_SIZE = 50000
    column_order = [
        "batch_id", "Datetime", "SyslogID", "Severity", "is_attack", "SourceIP", "SourcePort",
        "DestinationIP", "DestinationPort", "Duration", "Bytes", "Protocol",
        "Action", "Description", "raw_log"
    ]
    chunks = []
    total = sum(1 for _ in open(step1_out_path, encoding="utf-8"))
    processed = 0
    numeric_cols = ["SourcePort", "DestinationPort", "Duration", "Bytes"]

    # 這裡不以 Severity 決定 is_attack（避免草率）；先預設 0，交給後續規則/模型
    for chunk in tqdm(pd.read_csv(step1_out_path, chunksize=CHUNK_SIZE), desc=f"{Fore.CYAN}預處理進度", disable=not show_progress, total=total//CHUNK_SIZE+1):
        # 類別欄位映射
        for col, mapping in CATEGORICAL_MAPPINGS.items():
            if col in chunk.columns:
                chunk[col] = chunk[col].astype(str).str.lower().map(mapping).fillna(-1).astype(int)

        # 初判直接維持 0（模型/規則會再覆寫）
        chunk["is_attack"] = 0

        # 數值欄位
        for col in numeric_cols:
            if col in chunk.columns:
                chunk[col] = pd.to_numeric(chunk[col], errors="coerce").fillna(0).astype(int)

        # 欄位順序與補缺
        for col in column_order:
            if col not in chunk.columns:
                chunk[col] = ""
        chunk = chunk[column_order]
        chunks.append(chunk)
        processed += len(chunk)
        tqdm.write(f"{Fore.YELLOW}STEP2 累計預處理：{processed} 筆")

    df = pd.concat(chunks, ignore_index=True)
    before = len(df)
    df.drop_duplicates(inplace=True)
    after = len(df)
    print(f"{Fore.GREEN}去除重複資料 {before-after} 筆，共保留 {after} 筆")
    df.to_csv(step2_out_path, index=False, encoding="utf-8")
    print(f"{Fore.GREEN}{Style.BRIGHT}STEP2 完成：已輸出 {step2_out_path}")

# ========== STEP3-1：二元模型預測+圖表 ==========
def dflare_binary_predict(input_csv, binary_model_path, output_csv, output_pie, output_bar, feat_cols=None, show_progress=True):
    import matplotlib.pyplot as plt
    from matplotlib.font_manager import FontProperties
    from matplotlib.ticker import MaxNLocator, FuncFormatter
    import joblib
    import os

    if os.name == "nt":
        font_path = "C:/Windows/Fonts/msjh.ttc"
    elif os.path.exists("/System/Library/Fonts/PingFang.ttc"):
        font_path = "/System/Library/Fonts/PingFang.ttc"
    else:
        font_path = "/usr/share/fonts/truetype/arphic/uming.ttc"
    font_name = FontProperties(fname=font_path).get_name()
    plt.rcParams['font.family'] = font_name
    plt.rcParams['axes.unicode_minus'] = False
    plt.rcParams['figure.facecolor'] = "#fcfcfc"

    tqdm.write(f"{Fore.CYAN}{Style.BRIGHT}STEP3-1：載入預處理資料與二元模型...")
    df = pd.read_csv(input_csv, encoding="utf-8")
    bin_model = joblib.load(binary_model_path)

    # 特徵欄位自動對齊（只取模型訓練過的欄位）
    if hasattr(bin_model, "feature_names_in_"):
        model_feat_cols = list(bin_model.feature_names_in_)
    elif feat_cols is not None:
        model_feat_cols = feat_cols
    else:
        raise RuntimeError("二元模型未存特徵名稱，請明確指定 feat_cols。")
    df_model = df.reindex(columns=model_feat_cols, fill_value=-1)
    df_model = df_model.fillna(-1).astype(int)

    tqdm.write(f"{Fore.CYAN}{Style.BRIGHT}STEP3-1：二元模型預測與圖表產生中...")
    df['is_attack'] = bin_model.predict(df_model)
    df.to_csv(output_csv, index=False, encoding="utf-8")
    tqdm.write(f"{Fore.GREEN}{Style.BRIGHT}STEP3-1：二元判斷已輸出 {output_csv}")

    # 圖表
    is_attack_dist = df['is_attack'].value_counts().sort_index().reindex([0, 1], fill_value=0)
    values = [int(is_attack_dist.get(0, 0)), int(is_attack_dist.get(1, 0))]
    labels = ['正常流量', '攻擊流量']
    colors = ["#04ff11", "#FF0000"]

    draw_pie_with_side_legend(
        values=values,
        labels=labels,
        colors=colors,
        output_path=output_pie,
        title="攻擊與正常流量比例（二元）",
        decimals=2
    )

    # 長條：動態 Y 軸 + 千分位 + 置中數字
    plt.figure(figsize=(7, 5))
    ax = plt.gca()
    labels_attack = ['正常流量', '攻擊流量']
    pie_base_colors = ["#04ff11", "#FF0000"]
    vals = [int(is_attack_dist.loc[0]), int(is_attack_dist.loc[1])]
    y_top = dynamic_ylim_from_values(vals)

    plt.bar(labels_attack, vals, color=pie_base_colors, edgecolor="#333", width=0.6)
    ax.set_ylim(0, y_top)
    ax.yaxis.set_major_locator(MaxNLocator(integer=True))
    ax.yaxis.set_major_formatter(FuncFormatter(lambda x, _: f"{int(x):,}"))
    ax.yaxis.grid(True, linewidth=1, alpha=0.25)
    for spine in ['top','right']:
        ax.spines[spine].set_visible(False)
    for idx, v in enumerate(vals):
        y_lab = min(v + y_top * 0.05, y_top * 0.98)
        ax.text(idx, y_lab, f"{int(v):,}", ha='center', va='bottom', fontsize=13)

    ax.set_xlabel('流量類型', fontsize=15, labelpad=10)
    ax.set_ylabel('數量（筆）', fontsize=15, labelpad=10)
    ax.set_title('攻擊與正常流量數量分布（二元）', fontsize=18, pad=18)
    plt.tight_layout()
    plt.savefig(output_bar, bbox_inches='tight')
    plt.close()

    return {
        "output_csv": output_csv,
        "output_pie": output_pie,
        "output_bar": output_bar,
        "is_attack_distribution": is_attack_dist.to_dict(),
        "count_all": int(df.shape[0]),
        "count_attack": int(is_attack_dist[1]),
        "count_normal": int(is_attack_dist[0]),
    }, df

# ========== STEP3-2：多元模型預測+圖表 ==========
def dflare_multiclass_predict(df_attack, multiclass_model_path, output_csv, output_pie, output_bar, feat_cols=None, show_progress=True):
    import matplotlib.pyplot as plt
    from matplotlib.font_manager import FontProperties
    from matplotlib.ticker import MaxNLocator, FuncFormatter
    import joblib
    import os

    if os.name == "nt":
        font_path = "C:/Windows/Fonts/msjh.ttc"
    elif os.path.exists("/System/Library/Fonts/PingFang.ttc"):
        font_path = "/System/Library/Fonts/PingFang.ttc"
    else:
        font_path = "/usr/share/fonts/truetype/arphic/uming.ttc"
    font_name = FontProperties(fname=font_path).get_name()
    plt.rcParams['font.family'] = font_name
    plt.rcParams['axes.unicode_minus'] = False
    plt.rcParams['figure.facecolor'] = "#fcfcfc"

    severity_map = {1: '危險', 2: '高', 3: '中', 4: '低'}
    show_levels = [1, 2, 3, 4]
    sev_labels = [severity_map[i] for i in show_levels]
    colors_sev = ["#d32f2f", "#f57c08", "#fbc02d", "#04ff11"]

    tqdm.write(f"{Fore.CYAN}{Style.BRIGHT}STEP3-2：載入攻擊流量與多元模型...")

    mul_model = joblib.load(multiclass_model_path)
    if hasattr(mul_model, "feature_names_in_"):
        model_feat_cols = list(mul_model.feature_names_in_)
    elif feat_cols is not None:
        model_feat_cols = feat_cols
    else:
        raise RuntimeError("多元模型未存特徵名稱，請明確指定 feat_cols。")
    df_model = df_attack.reindex(columns=model_feat_cols, fill_value=-1)
    df_model = df_model.fillna(-1).astype(int)

    tqdm.write(f"{Fore.CYAN}{Style.BRIGHT}STEP3-2：多元模型分級與圖表產生中...")
    df_attack['Severity'] = mul_model.predict(df_model)
    df_attack.to_csv(output_csv, index=False, encoding="utf-8")
    tqdm.write(f"{Fore.GREEN}{Style.BRIGHT}STEP3-2：多元分級已輸出 {output_csv}")

    # 分佈（強制包含 1..4）
    sev_dist = df_attack['Severity'].value_counts().sort_index().reindex(show_levels, fill_value=0)
    vals = [int(sev_dist.loc[i]) for i in show_levels]

    # 圓餅
    draw_pie_with_side_legend(
        values=vals,
        labels=sev_labels,
        colors=colors_sev,
        output_path=output_pie,
        title="Severity 分布（僅針對攻擊流量）",
        decimals=2
    )

    # 長條：動態 Y 軸 + 千分位 + 置中數字
    plt.figure(figsize=(7, 5))
    ax = plt.gca(); ax.yaxis.set_major_locator(MaxNLocator(integer=True))
    y_top = dynamic_ylim_from_values(vals)
    ax.set_ylim(0, y_top)
    ax.yaxis.set_major_formatter(FuncFormatter(lambda x, _: f"{int(x):,}"))
    plt.bar(sev_labels, vals, color=colors_sev, edgecolor="#333", width=0.6)
    for idx, v in enumerate(vals):
        y_lab = min(v + y_top * 0.05, y_top * 0.98)
        plt.text(idx, y_lab, f"{int(v):,}", ha='center', va='bottom', fontsize=13)
    plt.xlabel('Severity 等級（4為最低，1為最高）', fontsize=15, labelpad=10)
    plt.ylabel('數量（筆）', fontsize=15, labelpad=10)
    plt.title('Severity 分布（僅針對攻擊流量）', fontsize=18, pad=20)
    plt.tight_layout(); plt.savefig(output_bar, bbox_inches='tight'); plt.close()

    return {
        "output_csv": output_csv,
        "output_pie": output_pie,
        "output_bar": output_bar,
        "severity_distribution": sev_dist.to_dict(),
        "count_all": int(df_attack.shape[0]),
        "message": "多元分級結果已產生"
    }

# ========== PIPELINE ==========
def dflare_sys_full_pipeline(
    raw_log_path, binary_model_path, multiclass_model_path, output_dir,
    all_results_csv="all_results.csv",
    bin_feat_cols=None, multi_feat_cols=None, show_progress=True,
    force_all_attack=False,
    overwrite_all_results=False,
    dedupe_all_results=False,
    whitelist_path=None
):
    os.makedirs(output_dir, exist_ok=True)

    # [1] 批次流水號
    all_results_path = os.path.join(output_dir, all_results_csv)
    batch_id = get_next_batch_id(all_results_path)

    # [2] 暫存檔
    step1_out = os.path.join(output_dir, "processed_logs.csv")
    unique_json = os.path.join(output_dir, "log_unique_values.json")
    step2_out = os.path.join(output_dir, "preprocessed_data.csv")
    binary_csv = os.path.join(output_dir, "binary_result.csv")
    binary_pie = os.path.join(output_dir, "binary_pie.png")
    binary_bar = os.path.join(output_dir, "binary_bar.png")
    multi_csv = os.path.join(output_dir, "multiclass_result.csv")
    multi_pie = os.path.join(output_dir, "multiclass_pie.png")
    multi_bar = os.path.join(output_dir, "multiclass_bar.png")
    alerts_json = os.path.join(output_dir, "alerts.json")

    # [3] ETL
    step1_process_logs(raw_log_path, step1_out, unique_json, batch_id, show_progress)
    step2_preprocess_data(step1_out, step2_out, unique_json, show_progress)

    # [4] 二元模型
    bin_res, df_bin = dflare_binary_predict(
        input_csv=step2_out,
        binary_model_path=binary_model_path,
        output_csv=binary_csv,
        output_pie=binary_pie,
        output_bar=binary_bar,
        feat_cols=bin_feat_cols,
        show_progress=show_progress
    )

    # === 覆寫：語意偵測 → 視窗統計 → 行為分級 → 介面/方向 → 白名單 → 極限保險 ===
    df_bin = apply_acl_deny_overlay(df_bin, window_sec=60)
    df_bin = apply_acl_strict_and_context(df_bin, window_sec=60)
    df_bin = add_acl_deny_window_stats(df_bin, window_sec=60)
    df_bin = overlay_acl_deny_scoring(df_bin)
    df_bin = parse_interfaces_and_direction(df_bin)
    df_bin = force_mark_acl_deny_anywhere(df_bin)
    df_bin["is_attack"] = pd.to_numeric(df_bin["is_attack"], errors="coerce").fillna(0).astype(int)

    ip_set, net_list = load_whitelist(whitelist_path) if whitelist_path else (set(), [])
    if ip_set or net_list:
        df_bin = apply_whitelist(df_bin, ip_set, net_list)

    df_bin = force_mark_acl_deny_anywhere(df_bin)  # 最後保險
    df_bin["is_attack"] = pd.to_numeric(df_bin["is_attack"], errors="coerce").fillna(0).astype(int)

    # 寫回 & 告警彙整（圖表稍後根據累積資料重新繪製）
    df_bin.to_csv(binary_csv, index=False, encoding="utf-8")
    build_alerts(df_bin, alerts_json)

    # [5] 多元模型（僅攻擊流量）
    print("=== PIPELINE DEBUG (is_attack 分佈) ===")
    print(df_bin["is_attack"].value_counts())
    df_attack = df_bin[df_bin['is_attack'] == 1].copy()
    if df_attack.empty:
        print(f"{Fore.YELLOW}{Style.BRIGHT}本批資料無攻擊流量（is_attack=1），跳過多元分級。")
        # [6] all_results 寫入
        df_bin["batch_id"] = batch_id
        if overwrite_all_results:
            df_bin.to_csv(all_results_path, index=False, encoding="utf-8")
        elif dedupe_all_results and os.path.exists(all_results_path):
            prev = pd.read_csv(all_results_path, encoding="utf-8")
            merged = pd.concat([prev, df_bin], ignore_index=True)
            if "raw_log" in merged.columns:
                merged = merged.drop_duplicates(subset=["raw_log"], keep="last")
            else:
                dedupe_keys = ["Datetime","SyslogID","SourceIP","SourcePort","DestinationIP","DestinationPort","Description"]
                dedupe_keys = [k for k in dedupe_keys if k in merged.columns]
                merged = merged.drop_duplicates(subset=dedupe_keys, keep="last")
            merged.to_csv(all_results_path, index=False, encoding="utf-8")
        else:
            write_header = not os.path.exists(all_results_path)
            with open(all_results_path, "a", newline='', encoding="utf-8") as allf:
                df_bin.to_csv(allf, header=write_header, index=False)
        # 重新讀取累積資料並更新圖表
        df_all = pd.read_csv(all_results_path, encoding="utf-8")
        _redraw_binary_charts_from_df(df_all, binary_pie, binary_bar)
        dist_all = df_all['is_attack'].value_counts().sort_index().reindex([0,1], fill_value=0)
        bin_res["is_attack_distribution"] = dist_all.to_dict()
        bin_res["count_all"] = int(df_all.shape[0])
        bin_res["count_attack"] = int(dist_all.get(1, 0))
        bin_res["count_normal"] = int(dist_all.get(0, 0))
        return {
            "batch_id": batch_id,
            "binary": bin_res,
            "multiclass": None,
            "binary_output_csv": binary_csv,
            "binary_output_pie": binary_pie,
            "binary_output_bar": binary_bar,
            "alerts_json": alerts_json,
            "multiclass_output_csv": None,
            "multiclass_output_pie": None,
            "multiclass_output_bar": None,
            "all_results_csv": all_results_path,
            "message": "本批無攻擊流量，已跳過多元分級"
        }

    # 有攻擊流量才進行多元分級
    multi_res = dflare_multiclass_predict(
        df_attack=df_attack,
        multiclass_model_path=multiclass_model_path,
        output_csv=multi_csv,
        output_pie=multi_pie,
        output_bar=multi_bar,
        feat_cols=multi_feat_cols,
        show_progress=show_progress
    )

    # [6] all_results 寫入
    df_bin["batch_id"] = batch_id
    if overwrite_all_results:
        df_bin.to_csv(all_results_path, index=False, encoding="utf-8")
    elif dedupe_all_results and os.path.exists(all_results_path):
        prev = pd.read_csv(all_results_path, encoding="utf-8")
        merged = pd.concat([prev, df_bin], ignore_index=True)
        if "raw_log" in merged.columns:
            merged = merged.drop_duplicates(subset=["raw_log"], keep="last")
        else:
            dedupe_keys = ["Datetime","SyslogID","SourceIP","SourcePort","DestinationIP","DestinationPort","Description"]
            dedupe_keys = [k for k in dedupe_keys if k in merged.columns]
            merged = merged.drop_duplicates(subset=dedupe_keys, keep="last")
        merged.to_csv(all_results_path, index=False, encoding="utf-8")
    else:
        write_header = not os.path.exists(all_results_path)
        with open(all_results_path, "a", newline='', encoding="utf-8") as allf:
            df_bin.to_csv(allf, header=write_header, index=False)

    # 重新讀取累積資料並更新圖表
    df_all = pd.read_csv(all_results_path, encoding="utf-8")
    _redraw_binary_charts_from_df(df_all, binary_pie, binary_bar)
    dist_all = df_all['is_attack'].value_counts().sort_index().reindex([0,1], fill_value=0)
    bin_res["is_attack_distribution"] = dist_all.to_dict()
    bin_res["count_all"] = int(df_all.shape[0])
    bin_res["count_attack"] = int(dist_all.get(1, 0))
    bin_res["count_normal"] = int(dist_all.get(0, 0))

    # [7] 回傳
    return {
        "batch_id": batch_id,
        "binary": bin_res,
        "multiclass": multi_res,
        "binary_output_csv": binary_csv,
        "binary_output_pie": binary_pie,
        "binary_output_bar": binary_bar,
        "alerts_json": alerts_json,
        "multiclass_output_csv": multi_csv,
        "multiclass_output_pie": multi_pie,
        "multiclass_output_bar": multi_bar,
        "all_results_csv": all_results_path,
    }

# ==================== CLI/GUI 共用主入口 ====================
if __name__ == "__main__":
    import argparse
    import tkinter as tk
    from tkinter import filedialog
    from tkinter import messagebox
    import os

    parser = argparse.ArgumentParser(
        description="D-FLARE SYS 全流程自動批次工具（Cisco ASA 5506-X）"
    )
    parser.add_argument('--raw_log', type=str, help='原始 log 檔路徑（csv/txt/gz）')
    parser.add_argument('--bin_model', type=str, help='二元模型 .pkl 路徑')
    parser.add_argument('--multi_model', type=str, help='多元模型 .pkl 路徑')
    parser.add_argument('--output_dir', type=str, help='所有輸出檔存放資料夾')
    parser.add_argument('--no_progress', action="store_true", help='不顯示進度條')
    parser.add_argument('--force_all_attack', action="store_true', help='本批資料全部視為攻擊（跳過二元誤判）")
    parser.add_argument('--overwrite_all_results', action="store_true",
                        help='不累積歷史，all_results.csv 直接覆蓋為本批結果')
    parser.add_argument('--dedupe_all_results', action="store_true",
                        help='累積歷史，但以 raw_log（或關鍵欄位）去重，保留較新批次')
    parser.add_argument('--whitelist', type=str, help='白名單檔案（每行 IP 或 CIDR）')
    args = parser.parse_args()

    # 用 tkinter 選檔 (互動)
    def pick_file(title="請選擇檔案", filetypes=[("所有檔案", "*.*")]):
        root = tk.Tk(); root.withdraw()
        file_path = filedialog.askopenfilename(title=title, filetypes=filetypes)
        root.destroy(); return file_path

    def pick_folder(title="請選擇資料夾"):
        root = tk.Tk(); root.withdraw()
        folder_path = filedialog.askdirectory(title=title)
        root.destroy(); return folder_path

    # 檢查參數，若沒指定就互動選擇
    raw_log = args.raw_log or pick_file("請選擇原始 log 檔", [("CSV", "*.csv"), ("文字", "*.txt"), ("GZ", "*.gz"), ("所有檔案", "*.*")])
    bin_model = args.bin_model or pick_file("請選擇二元模型 .pkl 檔", [("Pickle", "*.pkl")])
    multi_model = args.multi_model or pick_file("請選擇多元模型 .pkl 檔", [("Pickle", "*.pkl")])
    output_dir = args.output_dir or pick_folder("請選擇輸出資料夾")
    show_progress = not args.no_progress

    print(f"{Fore.CYAN}{Style.BRIGHT}🚦 啟動 D-FLARE SYS 全流程 Pipeline（二元+多元，含語意覆寫/行為分級/白名單/告警彙整）...")
    t0 = time.time()
    result = dflare_sys_full_pipeline(
        raw_log_path=raw_log,
        binary_model_path=bin_model,
        multiclass_model_path=multi_model,
        output_dir=output_dir,
        bin_feat_cols=None,
        multi_feat_cols=None,
        show_progress=show_progress,
        force_all_attack=args.force_all_attack,
        overwrite_all_results=args.overwrite_all_results,
        dedupe_all_results=args.dedupe_all_results,
        whitelist_path=args.whitelist
    )
    print(f"{Fore.GREEN}{Style.BRIGHT}🚀 全流程完成！結果已輸出至：{output_dir}")
    print(json.dumps(result, ensure_ascii=False, indent=2))
    print(f"{Fore.CYAN}{Style.BRIGHT}總耗時：{time.time() - t0:.1f} 秒。")
