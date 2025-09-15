# dflare_sys.py（非阻塞穩定版｜累加CSV＋防卡頓）
"""
D-FLARE SYS — 多層集成式防火牆威脅分級系統（Cisco ASA 5506-X 專用）
- 重要改動（防卡頓）：
  1) Matplotlib 使用 Agg 後端，完全不佔用 GUI 資源。
  2) Discord 推播僅用彙整去重，提供最小更新間隔，避免刷屏與阻塞。
  3) step1 唯一值統計加上上限，避免超大資料集吃爆記憶體。
  4) 累積檔（all_results.csv / all_multiclass_results.csv）改為 **直接附加**，
     圖表分佈用 **chunk 讀取統計**，不再把整檔載入記憶體，避免大檔造成卡頓。
  5) 移除 tkinter 互動選檔（避免卡住主流程），統一改用 CLI 參數。

- 圖表仍會輸出 PNG，但繪圖本身不會影響 UI（Agg + 關閉圖窗）。
- 若要進一步將整個流程與 UI 解耦，請搭配我提供的 PyQt 非阻塞骨架整合。
"""

import os
import sys
import csv
import json
import time
import math
import ipaddress
import pandas as pd
from tqdm import tqdm
from colorama import init, Fore, Style

# ===== 防卡頓：使用非 GUI 後端 =====
import matplotlib
matplotlib.use("Agg")  # 不使用任何互動式後端，避免阻塞 UI

# 繪圖
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec

# 百分比四捨五入（兩位小數）
from decimal import Decimal, ROUND_HALF_UP

import requests
import hashlib
import re

# 初始化 colorama
init(autoreset=True)

# ==================== 基礎工具 ====================

def _coerce_severity(series: pd.Series) -> pd.Series:
    """把 Severity 安全轉為 1~4 的整數，無法解析設為 NaN，方便後續 reindex。"""
    s = pd.to_numeric(series, errors="coerce")
    return s

_FLOOD_PAT = re.compile(r"(?:\bflood\b|syn\s*flood|rst\s*flood|embryonic)", re.I)

def _is_flood_text(s: str) -> bool:
    if not s:
        return False
    return bool(_FLOOD_PAT.search(s))

def _make_struct_signature(rows: pd.DataFrame) -> tuple[str, bool]:
    """
    依「是否含洪水」+ 「Severity-SyslogID 組合」產生結構簽章（與數量無關）。
    用於去重，避免相同類型在短時間內重複推播。
    """
    has_flood = bool(rows.get("is_flood", pd.Series(dtype=bool))).any()
    keys = set()
    for _, r in rows.iterrows():
        sev = int(r["Severity"]) if pd.notna(r["Severity"]) else 0
        sid = str(r["SyslogID"]) if pd.notna(r["SyslogID"]) else "?"
        keys.add(f"{sev}-{sid}")
    base = ("FLOOD|" if has_flood else "GEN|") + "|".join(sorted(keys))
    return hashlib.sha1(base.encode("utf-8", errors="ignore")).hexdigest(), has_flood

def _agg_for_discord(df_attack: pd.DataFrame) -> tuple[str, bool, int, list[str]]:
    """
    將攻擊流量彙整成「sev+syslog_id」清單與簽章。
    預設包含 Severity 1~4，若要只含 1~3 可自行調整。
    """
    if df_attack.empty:
        return "", False, 0, []

    tmp = df_attack.copy()
    # 判斷洪水
    text = (tmp.get("Description", "").astype(str) + " " + tmp.get("raw_log", "").astype(str))
    tmp["is_flood"] = text.apply(_is_flood_text)

    # 取 sev 1~4
    tmp["Severity"] = _coerce_severity(tmp.get("Severity", pd.Series(dtype=float)))
    tmp = tmp[tmp["Severity"].isin([1, 2, 3, 4])]

    if tmp.empty:
        return "", False, 0, []

    grp = tmp.groupby(["Severity", "SyslogID", "is_flood"], dropna=False).size().reset_index(name="count")

    sig, has_flood = _make_struct_signature(grp)
    total = int(grp["count"].sum())
    lines = []
    # 排序：Severity 由高到低(1→4)，同層依數量多→少
    grp = grp.sort_values(by=["Severity", "count"], ascending=[True, False])
    for _, r in grp.iterrows():
        sev = int(r["Severity"])  # 1 高 → 4 低
        sid = str(r["SyslogID"]) if pd.notna(r["SyslogID"]) else "?"
        cnt = int(r["count"])
        suf = " (FLOOD)" if bool(r["is_flood"]) else ""
        lines.append(f"sev{sev} id{sid} x{cnt}{suf}")

    return sig, has_flood, total, lines

# ---- 輕量狀態檔 I/O ----

def _load_state(path: str) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

def _save_state(path: str, data: dict):
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    except Exception:
        pass

# ---- 非阻塞：縮短 timeout，避免等待卡死 ----

def _discord_post(url: str, content: str) -> str | None:
    try:
        r = requests.post(url.rstrip("/") + "?wait=true", json={"content": content}, timeout=3)
        if r.status_code in (200, 204):
            try:
                data = r.json()
                return str(data.get("id")) if isinstance(data, dict) else None
            except Exception:
                return None
    except Exception:
        return None

def _discord_patch(url: str, message_id: str, content: str) -> bool:
    try:
        r = requests.patch(url.rstrip("/") + f"/messages/{message_id}", json={"content": content}, timeout=3)
        return r.status_code in (200, 204)
    except Exception:
        return False

# ---- 彙整+去重+最小間隔，避免刷屏和頻繁網路卡頓 ----

def notify_discord_dedup(
    df_attack: pd.DataFrame,
    webhook_url: str,
    state_path: str,
    batch_id: int,
    dedup_sec: int = 120,
    growth_ratio: float = 0.5,
    update_instead: bool = True,
    *,
    only_once: bool = True,           # ★ 新增：預設 one-shot，後續一律跳過
    only_once_update: bool = False,   # ★ 或用這個：後續只 PATCH，不再 POST 新訊息
) -> dict:
    """
    - one-shot 模式：
      only_once=True            → 同簽章只發一次，其後永遠 skip。
      only_once_update=True     → 同簽章只發一次，其後僅 PATCH 更新；若 PATCH 失敗也跳過（不新開）。

    - 若兩者皆為 False，則使用原本「視窗+成長比例」策略，但做一個關鍵改動：
      當 PATCH 失敗時『不再 fallback 為 POST』，避免刷屏。
    """
    assert not (only_once and only_once_update), "only_once 與 only_once_update 請擇一"

    sig, has_flood, total, lines = _agg_for_discord(df_attack)
    if not lines:
        return {"action": "skip", "message_id": None, "reason": "no_lines"}

    title = "🚨 洪水/異常高流量摘要" if has_flood else f"事件摘要（批次 {batch_id}）"
    content = title + "\n" + "\n".join(lines[:25])

    state = _load_state(state_path)
    now = time.time()
    prev = state.get(sig)

    # ---------- one-shot（只發一次） ----------
    if prev is not None:
        # 已經發過
        if only_once:
            return {"action": "skip", "message_id": prev.get("message_id"), "reason": "only_once"}
        if only_once_update:
            mid = prev.get("message_id")
            if mid:
                # 只嘗試 PATCH，不成功也不開新訊息（避免重複）
                ok = _discord_patch(webhook_url, mid, content)
                if ok:
                    prev.update({"ts": now, "count": total})
                    state[sig] = prev
                    _save_state(state_path, state)
                    return {"action": "update", "message_id": mid}
                else:
                    return {"action": "skip", "message_id": mid, "reason": "patch_failed_skip"}
            else:
                # 理論上不會發生，但保險處理：補發一次後就固定用這則
                mid = _discord_post(webhook_url, content)
                state[sig] = {"ts": now, "count": total, "message_id": mid}
                _save_state(state_path, state)
                return {"action": "send", "message_id": mid}

    # 還沒發過
    if only_once or only_once_update:
        mid = _discord_post(webhook_url, content)
        state[sig] = {"ts": now, "count": total, "message_id": mid}
        _save_state(state_path, state)
        return {"action": "send", "message_id": mid}

    # ---------- 傳統去重（時間窗 + 成長比例），但禁止 PATCH 失敗後 fallback 為 POST ----------
    if (prev is None) or (now - float(prev.get("ts", 0)) > dedup_sec):
        mid = _discord_post(webhook_url, content)
        state[sig] = {"ts": now, "count": total, "message_id": mid}
        _save_state(state_path, state)
        return {"action": "send", "message_id": mid}

    # 視窗內 → 檢查成長比例
    prev_cnt = max(int(prev.get("count", 1)), 1)
    growth = (total - prev_cnt) / prev_cnt
    if growth >= growth_ratio:
        if update_instead and prev.get("message_id"):
            ok = _discord_patch(webhook_url, prev["message_id"], content)
            if ok:
                prev.update({"ts": now, "count": total})
                state[sig] = prev
                _save_state(state_path, state)
                return {"action": "update", "message_id": prev["message_id"]}
            # 關鍵改動：PATCH 失敗 → 直接 skip（不再 POST 新訊息以避免刷屏）
            return {"action": "skip", "message_id": prev.get("message_id"), "reason": "patch_failed_skip"}

    return {"action": "skip", "message_id": prev.get("message_id"), "reason": "growth_below_threshold"}


    title = "🚨 洪水/異常高流量摘要" if has_flood else f"事件摘要（批次 {batch_id}）"
    content = title + "\n" + "\n".join(lines[:25])

    state = _load_state(state_path)
    now = time.time()
    prev = state.get(sig)

    # 新事件或過期 → 發新訊息
    if (prev is None) or (now - float(prev.get("ts", 0)) > dedup_sec):
        mid = _discord_post(webhook_url, content)
        state[sig] = {"ts": now, "count": total, "message_id": mid, "last_patch": now}
        _save_state(state_path, state)
        return {"action": "send", "message_id": mid}

    # 視窗內 → 檢查成長比例 + 最小更新間隔
    prev_cnt = max(int(prev.get("count", 1)), 1)
    growth = (total - prev_cnt) / prev_cnt
    last_patch = float(prev.get("last_patch", prev.get("ts", 0)))
    if (growth >= growth_ratio) and (now - last_patch >= min_update_interval_sec):
        if update_instead and prev.get("message_id"):
            ok = _discord_patch(webhook_url, prev["message_id"], content)
            if ok:
                prev.update({"ts": now, "count": total, "last_patch": now})
                state[sig] = prev
                _save_state(state_path, state)
                return {"action": "update", "message_id": prev["message_id"]}
        # PATCH 失敗或不更新 → 發新訊息
        mid = _discord_post(webhook_url, content)
        state[sig] = {"ts": now, "count": total, "message_id": mid, "last_patch": now}
        _save_state(state_path, state)
        return {"action": "send", "message_id": mid}

    # 成長不足或間隔未到 → skip（不觸網路）
    prev["ts"] = now
    state[sig] = prev
    _save_state(state_path, state)
    return {"action": "skip", "message_id": prev.get("message_id")}


def ceil_to_step(max_val, step=500, minimum=500):
    try:
        m = float(max_val)
    except Exception:
        return minimum
    if m <= 0:
        return minimum
    return int(np.ceil(m / step) * step)

def format_pct2(pct_value: float) -> str:
    d = Decimal(str(pct_value)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    return f"{d:.2f}%"

# ==================== 圖表工具 ====================

def draw_pie_with_side_legend(values, labels, colors, output_path,
                              title="", startangle=90, edgecolor="#FFFFFF",
                              show_total=True, total_label="合計", dpi=150,
                              decimals=2):
    vals = np.array(values, dtype=float)
    total = vals.sum()
    if total <= 0:
        plt.figure(figsize=(8, 5), dpi=dpi)
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

    ax_pie.pie(vals, labels=None, colors=colors, startangle=startangle,
               wedgeprops=dict(edgecolor=edgecolor, linewidth=2))
    ax_pie.set_aspect('equal')
    if title:
        ax_pie.set_title(title, fontsize=18, pad=16)

    ax_leg.axis('off'); ax_leg.set_xlim(0, 1); ax_leg.set_ylim(0, 1)
    pct = vals / total * 100.0
    ax_leg.text(0.05, 0.95, "區域", fontsize=12, weight='bold', va='center')
    ax_leg.text(0.78, 0.95, "占比", fontsize=12, weight='bold', va='center')
    ax_leg.hlines(0.90, 0.03, 0.97, colors="#bdbdbd", linewidth=1)

    n = len(labels); top = 0.85; row_h = 0.12 if n <= 4 else 0.09
    for i, (lab, p, c) in enumerate(zip(labels, pct, colors)):
        y = top - i * row_h
        ax_leg.scatter(0.07, y, s=220, color=c)
        ax_leg.text(0.12, y, str(lab), fontsize=12, va='center')
        ax_leg.text(0.95, y, format_pct2(p), fontsize=12, va='center', ha='right')

    if show_total:
        ax_leg.hlines(top - n * row_h - 0.03, 0.03, 0.97, colors="#bdbdbd", linewidth=1)
        ax_leg.text(0.12, top - n * row_h - 0.10, total_label, fontsize=12, va='center')
        ax_leg.text(0.95, top - n * row_h - 0.10, "100.00%", fontsize=12, va='center', ha='right')

    fig.patch.set_facecolor("#fcfcfc")
    plt.tight_layout()
    plt.savefig(output_path, bbox_inches='tight', dpi=dpi)
    plt.close()

# ====== 圖表：動態 Y 軸工具函式 ======

def dynamic_ylim_from_values(vals):
    m = int(max(vals)) if vals else 0
    if m <= 0:
        return 8
    target = m * 1.15
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

# 直接用計數繪圖（免載入整檔）

def draw_binary_charts_from_counts(count_normal: int, count_attack: int, output_pie: str, output_bar: str):
    from matplotlib.ticker import MaxNLocator, FuncFormatter
    labels = ['正常流量', '攻擊流量']
    colors = ["#04ff11", "#FF0000"]
    values = [int(count_normal), int(count_attack)]
    draw_pie_with_side_legend(values, labels, colors, output_pie, title="攻擊與正常流量比例（二元）", decimals=2)

    plt.figure(figsize=(7, 5))
    ax = plt.gca()
    y_top = dynamic_ylim_from_values(values)
    plt.bar(labels, values, edgecolor="#333", width=0.6)
    ax.set_ylim(0, y_top)
    ax.yaxis.set_major_locator(MaxNLocator(integer=True))
    ax.yaxis.set_major_formatter(FuncFormatter(lambda x, _: f"{int(x):,}"))
    ax.yaxis.grid(True, linewidth=1, alpha=0.25)
    for spine in ['top', 'right']:
        ax.spines[spine].set_visible(False)
    for idx, v in enumerate(values):
        y_lab = min(v + y_top * 0.05, y_top * 0.98)
        ax.text(idx, y_lab, f"{int(v):,}", ha='center', va='bottom', fontsize=13)
    ax.set_xlabel('流量類型', fontsize=15, labelpad=10)
    ax.set_ylabel('數量（筆）', fontsize=15, labelpad=10)
    ax.set_title('攻擊與正常流量數量分布（二元）', fontsize=18, pad=18)
    plt.tight_layout(); plt.savefig(output_bar, bbox_inches='tight'); plt.close()


def draw_multiclass_charts_from_counts(sev_counts: dict[int, int], output_pie: str, output_bar: str):
    from matplotlib.ticker import MaxNLocator, FuncFormatter
    severity_map = {1: '危險', 2: '高', 3: '中', 4: '低'}
    show_levels = [1, 2, 3, 4]
    sev_labels = [severity_map[i] for i in show_levels]
    colors_sev = ["#d32f2f", "#f57c08", "#fbc02d", "#04ff11"]
    vals = [int(sev_counts.get(i, 0)) for i in show_levels]

    draw_pie_with_side_legend(vals, sev_labels, colors_sev, output_pie, title="Severity 分布（僅針對攻擊流量）", decimals=2)

    plt.figure(figsize=(7, 5))
    ax = plt.gca(); ax.yaxis.set_major_locator(MaxNLocator(integer=True))
    y_top = dynamic_ylim_from_values(vals)
    ax.set_ylim(0, y_top)
    ax.yaxis.set_major_formatter(FuncFormatter(lambda x, _: f"{int(x):,}"))
    plt.bar(sev_labels, vals, edgecolor="#333", width=0.6)
    for idx, v in enumerate(vals):
        y_lab = min(v + y_top * 0.05, y_top * 0.98)
        plt.text(idx, y_lab, f"{int(v):,}", ha='center', va='bottom', fontsize=13)
    plt.xlabel('Severity 等級（4為最低，1為最高）', fontsize=15, labelpad=10)
    plt.ylabel('數量（筆）', fontsize=15, labelpad=10)
    plt.title('Severity 分布（僅針對攻擊流量）', fontsize=18, pad=20)
    plt.tight_layout(); plt.savefig(output_bar, bbox_inches='tight'); plt.close()

# ==================== ACL 規則與覆寫（可選） ====================

ATTEMPT_DENY_IDS = {"710003", "106023", "106021", "106016", "106015", "106014", "106006"}

def _normalize_columns(df: pd.DataFrame) -> pd.DataFrame:
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

    df["is_attack"] = pd.to_numeric(df["is_attack"], errors="coerce").fillna(0).astype(int)
    df["blocked"] = pd.to_numeric(df["blocked"], errors="coerce").fillna(0).astype(int)
    return df

# ---------- 介面/方向抽取 ----------

def parse_interfaces_and_direction(df: pd.DataFrame) -> pd.DataFrame:
    import re
    df = _normalize_columns(df)
    text = (df["Description"].astype(str) + " " + df["raw_log"].astype(str))

    m_to = text.str.extract(r"\bto\s+([A-Za-z0-9_-]+):\d+\.\d+\.\d+\.\d+/\d+", expand=True)
    m_on = text.str.extract(r"on\s+interface\s+([A-Za-z0-9_-]+)", expand=True)

    df.loc[m_to[0].notna(), "dst_if"] = m_to[0]
    df.loc[m_on[0].notna() & df["dst_if"].eq(""), "dst_if"] = m_on[0]

    def infer_dir(row):
        if row["dst_if"]:
            txt = f"{row['Description']} {row['raw_log']}".lower()
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

# ---------- 語意偵測（選用） ----------

def semantic_attack_labels(df: pd.DataFrame) -> pd.DataFrame:
    df = _normalize_columns(df)
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
    import numpy as np
    df = _normalize_columns(df)
    if "Datetime" not in df.columns or "event_id" not in df.columns:
        df["deny_cnt_60"] = 0; df["deny_u_dport_60"] = 0; df["deny_u_dip_60"] = 0
        return df

    mask = df["event_id"].astype(str).isin(ATTEMPT_DENY_IDS)
    if not mask.any():
        df["deny_cnt_60"] = 0; df["deny_u_dport_60"] = 0; df["deny_u_dip_60"] = 0
        return df

    d = df.copy()
    d["Datetime"] = pd.to_datetime(d["Datetime"], errors="coerce")
    d = d.sort_values("Datetime")

    d["deny_cnt_60"] = 0; d["deny_u_dport_60"] = 0; d["deny_u_dip_60"] = 0

    idxs = d[mask].index
    for idx in idxs:
        t = d.at[idx, "Datetime"]
        if pd.isna(t):
            continue
        eid = str(d.at[idx, "event_id"])
        window_start = t - pd.Timedelta(seconds=window_sec)
        win = d[(d["Datetime"] >= window_start) & (d["Datetime"] <= t) & (d["event_id"].astype(str) == eid)]
        d.at[idx, "deny_cnt_60"] = len(win)
        d.at[idx, "deny_u_dport_60"] = win["DestinationPort"].nunique() if "DestinationPort" in win.columns else 0
        d.at[idx, "deny_u_dip_60"] = win["DestinationIP"].nunique() if "DestinationIP" in win.columns else 0

    for c in ["deny_cnt_60", "deny_u_dport_60", "deny_u_dip_60"]:
        df[c] = d[c]
    return df


def overlay_acl_deny_rules(df: pd.DataFrame) -> pd.DataFrame:
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
    df_pred = add_acl_deny_window_stats(df_pred, window_sec=window_sec)
    df_pred = overlay_acl_deny_rules(df_pred)
    df_pred = overlay_acl_deny_scoring(df_pred)
    return df_pred

# =============== 累積輸出/圖表（非阻塞版） ===============

# 以「附加寫入 + chunk 統計」避免載入整檔造成卡頓

def save_all_results_and_redraw(
    df_bin: pd.DataFrame,
    batch_id: int,
    all_results_path: str,
    binary_pie: str,
    binary_bar: str,
    overwrite: bool = False,   # 參數保留但不使用（固定附加）
    dedupe: bool = False,      # 大檔去重很吃記憶體，預設關閉
):
    df_save = df_bin.copy()
    df_save["batch_id"] = batch_id

    # 直接附加（避免將舊檔整個載入記憶體）
    write_header = not os.path.exists(all_results_path)
    with open(all_results_path, "a", newline='', encoding="utf-8") as allf:
        df_save.to_csv(allf, header=write_header, index=False)

    # 如需去重，僅針對本批資料與最近 N 行做極小範圍處理（此處略，保持非阻塞）

    # 以 chunk 讀取統計（只讀 is_attack 欄）
    cnt0, cnt1 = 0, 0
    try:
        for ch in pd.read_csv(all_results_path, usecols=["is_attack"], chunksize=200_000):
            vc = ch["is_attack"].value_counts()
            cnt0 += int(vc.get(0, 0))
            cnt1 += int(vc.get(1, 0))
    except Exception:
        pass

    # 依計數畫圖
    draw_binary_charts_from_counts(cnt0, cnt1, binary_pie, binary_bar)

    return {"count_all": cnt0 + cnt1, "count_normal": cnt0, "count_attack": cnt1}


def save_all_multiclass_results_and_redraw(
    df_attack_with_sev: pd.DataFrame,
    batch_id: int,
    all_multi_path: str,
    multi_all_pie: str,
    multi_all_bar: str,
    overwrite: bool = False,  # 保留但不使用（固定附加）
    dedupe: bool = False,     # 預設關閉，避免卡頓
):
    """將本批攻擊(含 Severity)寫入 all_multiclass_results.csv，並用 chunk 統計重繪圖表。"""
    df_save = df_attack_with_sev.copy()
    df_save["batch_id"] = batch_id

    write_header = not os.path.exists(all_multi_path)
    with open(all_multi_path, "a", newline='', encoding="utf-8") as allf:
        df_save.to_csv(allf, header=write_header, index=False)

    # 以 chunk 讀取 Severity 統計
    sev_counts = {1: 0, 2: 0, 3: 0, 4: 0}
    try:
        for ch in pd.read_csv(all_multi_path, usecols=["Severity"], chunksize=200_000):
            vc = pd.to_numeric(ch["Severity"], errors="coerce").value_counts()
            for k in (1, 2, 3, 4):
                sev_counts[k] += int(vc.get(k, 0))
    except Exception:
        pass

    draw_multiclass_charts_from_counts(sev_counts, multi_all_pie, multi_all_bar)

    return {"count_all": sum(sev_counts.values()), "severity_distribution": sev_counts}

# =============== STEP1 ===============

def step1_process_logs(raw_log_path, step1_out_path, unique_out_json, batch_id, show_progress=True):
    import gzip, io
    import chardet

    STANDARD_COLUMNS = [
        "batch_id", "Datetime", "SyslogID", "Severity", "SourceIP", "SourcePort",
        "DestinationIP", "DestinationPort", "Duration", "Bytes",
        "Protocol", "Action", "Description", "raw_log"
    ]

    # 防記憶體暴衝：每欄唯一值只記到這個上限
    MAX_UNIQUES_PER_COL = 1000
    unique_vals = {col: set() for col in STANDARD_COLUMNS}

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
                for chunk in iter(lambda: f.read(bufsize), b""):
                    total += chunk.count(b"\n")
        else:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(bufsize), b""):
                    total += chunk.count(b"\n")
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

            for row in pbar:
                record = {col: row.get(col, "") for col in STANDARD_COLUMNS if col != "batch_id" and col != "raw_log"}
                record["batch_id"] = batch_id
                record["raw_log"] = json.dumps(row, ensure_ascii=False)
                for col in STANDARD_COLUMNS:
                    if col not in record:
                        record[col] = "unknown"
                    # 限制唯一值集合大小，避免爆記憶體
                    if len(unique_vals[col]) < MAX_UNIQUES_PER_COL:
                        unique_vals[col].add(record[col])
                writer.writerow(record)
                processed_count += 1
        print(f"{Fore.GREEN}{Style.BRIGHT}STEP1 結束，共處理 {processed_count} 筆資料。")
    finally:
        try:
            f.close()
        except Exception:
            pass

    unique_json = {k: sorted([str(x) for x in v]) for k, v in unique_vals.items()}
    with open(unique_out_json, "w", encoding="utf-8") as fjson:
        json.dump(unique_json, fjson, ensure_ascii=False, indent=4)
    print(f"{Fore.GREEN}{Style.BRIGHT}STEP1 完成：已輸出 {step1_out_path} 及 {unique_out_json}")

# =============== STEP2 ===============

def step2_preprocess_data(step1_out_path, step2_out_path, unique_json, show_progress=True):
    with open(unique_json, "r", encoding="utf-8") as f:
        unique_vals = json.load(f)
    CATEGORICAL_MAPPINGS = {
        "Protocol": {"http": 1, "https": 2, "icmp": 3, "tcp": 4, "udp": 5, "scan": 6, "flood": 7, "other": 8, "unknown": 0, "nan": -1},
        "Action": {"built": 1, "teardown": 2, "deny": 3, "drop": 4, "login": 5, "other": 6, "unknown": 0, "nan": -1}
    }
    print(f"{Fore.CYAN}{Style.BRIGHT}STEP2：開始欄位標準化與映射")

    column_order = [
        "batch_id", "Datetime", "SyslogID", "Severity", "is_attack", "SourceIP", "SourcePort",
        "DestinationIP", "DestinationPort", "Duration", "Bytes", "Protocol",
        "Action", "Description", "raw_log"
    ]
    chunks = []
    numeric_cols = ["SourcePort", "DestinationPort", "Duration", "Bytes"]

    for chunk in tqdm(pd.read_csv(step1_out_path, chunksize=50_000),
                      desc=f"{Fore.CYAN}預處理進度", disable=not show_progress):
        for col, mapping in CATEGORICAL_MAPPINGS.items():
            if col in chunk.columns:
                chunk[col] = chunk[col].astype(str).str.lower().map(mapping).fillna(-1).astype(int)
        chunk["is_attack"] = 0
        for col in numeric_cols:
            if col in chunk.columns:
                chunk[col] = pd.to_numeric(chunk[col], errors="coerce").fillna(0).astype(int)
        for col in column_order:
            if col not in chunk.columns:
                chunk[col] = ""
        chunk = chunk[column_order]
        chunks.append(chunk)

    df = pd.concat(chunks, ignore_index=True)
    before = len(df)
    df.drop_duplicates(inplace=True)
    after = len(df)
    print(f"{Fore.GREEN}去除重複資料 {before-after} 筆，共保留 {after} 筆")
    df.to_csv(step2_out_path, index=False, encoding="utf-8")
    print(f"{Fore.GREEN}{Style.BRIGHT}STEP2 完成：已輸出 {step2_out_path}")

# ========== STEP3-1：二元模型預測+圖表 ==========

def dflare_binary_predict(input_csv, binary_model_path, output_csv, output_pie, output_bar, feat_cols=None, show_progress=True):
    from matplotlib.font_manager import FontProperties
    from matplotlib.ticker import MaxNLocator, FuncFormatter
    import joblib

    # 字型設定（跨平台）
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

    if hasattr(bin_model, "feature_names_in_"):
        model_feat_cols = list(bin_model.feature_names_in_)
    elif feat_cols is not None:
        model_feat_cols = feat_cols
    else:
        raise RuntimeError("二元模型未存特徵名稱，請明確指定 feat_cols。")
    df_model = df.reindex(columns=model_feat_cols, fill_value=-1).fillna(-1).astype(int)

    tqdm.write(f"{Fore.CYAN}{Style.BRIGHT}STEP3-1：二元模型預測與圖表產生中...")
    df['is_attack'] = bin_model.predict(df_model)
    df.to_csv(output_csv, index=False, encoding="utf-8")
    tqdm.write(f"{Fore.GREEN}{Style.BRIGHT}STEP3-1：二元判斷已輸出 {output_csv}")

    is_attack_dist = df['is_attack'].value_counts().sort_index().reindex([0, 1], fill_value=0)
    values = [int(is_attack_dist.get(0, 0)), int(is_attack_dist.get(1, 0))]
    labels = ['正常流量', '攻擊流量']
    colors = ["#04ff11", "#FF0000"]

    draw_pie_with_side_legend(values, labels, colors, output_pie, title="攻擊與正常流量比例（二元）", decimals=2)

    plt.figure(figsize=(7, 5))
    ax = plt.gca()
    vals = [int(is_attack_dist.loc[0]), int(is_attack_dist.loc[1])]
    y_top = dynamic_ylim_from_values(vals)
    plt.bar(labels, vals, edgecolor="#333", width=0.6)
    ax.set_ylim(0, y_top)
    ax.yaxis.set_major_locator(MaxNLocator(integer=True))
    ax.yaxis.set_major_formatter(FuncFormatter(lambda x, _: f"{int(x):,}"))
    ax.yaxis.grid(True, linewidth=1, alpha=0.25)
    for spine in ['top', 'right']:
        ax.spines[spine].set_visible(False)
    for idx, v in enumerate(vals):
        y_lab = min(v + y_top * 0.05, y_top * 0.98)
        ax.text(idx, y_lab, f"{int(v):,}", ha='center', va='bottom', fontsize=13)
    ax.set_xlabel('流量類型', fontsize=15, labelpad=10)
    ax.set_ylabel('數量（筆）', fontsize=15, labelpad=10)
    ax.set_title('攻擊與正常流量數量分布（二元）', fontsize=18, pad=18)
    plt.tight_layout(); plt.savefig(output_bar, bbox_inches='tight'); plt.close()

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
    from matplotlib.font_manager import FontProperties
    from matplotlib.ticker import MaxNLocator, FuncFormatter
    import joblib

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
    df_model = df_attack.reindex(columns=model_feat_cols, fill_value=-1).fillna(-1).astype(int)

    tqdm.write(f"{Fore.CYAN}{Style.BRIGHT}STEP3-2：多元模型分級與圖表產生中...")
    df_attack['Severity'] = mul_model.predict(df_model)
    df_attack.to_csv(output_csv, index=False, encoding="utf-8")
    tqdm.write(f"{Fore.GREEN}{Style.BRIGHT}STEP3-2：多元分級已輸出 {output_csv}")

    sev_dist = df_attack['Severity'].value_counts().sort_index().reindex(show_levels, fill_value=0)
    vals = [int(sev_dist.loc[i]) for i in show_levels]

    draw_pie_with_side_legend(vals, sev_labels, colors_sev, output_pie, title="Severity 分布（僅針對攻擊流量）", decimals=2)

    plt.figure(figsize=(7, 5))
    ax = plt.gca(); ax.yaxis.set_major_locator(MaxNLocator(integer=True))
    y_top = dynamic_ylim_from_values(vals)
    ax.set_ylim(0, y_top)
    ax.yaxis.set_major_formatter(FuncFormatter(lambda x, _: f"{int(x):,}"))
    plt.bar(sev_labels, vals, edgecolor="#333", width=0.6)
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
    }, df_attack

# ========== PIPELINE ==========

def dflare_sys_full_pipeline(
    raw_log_path, binary_model_path, multiclass_model_path, output_dir,
    all_results_csv="all_results.csv",
    all_multiclass_csv="all_multiclass_results.csv",
    bin_feat_cols=None, multi_feat_cols=None, show_progress=True,
    force_all_attack=False,
    overwrite_all_results=False,
    dedupe_all_results=False,
    whitelist_path=None,
    discord_webhook_url: str | None = None,
    notify_dedup_sec: int = 120,
    notify_growth_ratio: float = 0.5,
    notify_update_instead: bool = True,
    notify_min_interval_sec: int = 5,
    only_once=True
) -> dict:
    os.makedirs(output_dir, exist_ok=True)

    # [1] 批次流水號
    all_results_path = os.path.join(output_dir, all_results_csv)
    all_multi_path = os.path.join(output_dir, all_multiclass_csv)
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
    multi_all_pie = os.path.join(output_dir, "multiclass_pie_all.png")
    multi_all_bar = os.path.join(output_dir, "multiclass_bar_all.png")
    alerts_json = os.path.join(output_dir, "alerts.json")
    discord_state_json = os.path.join(output_dir, "discord_state.json")  # 去重狀態

    # [3] ETL
    step1_process_logs(raw_log_path, step1_out, unique_json, batch_id, show_progress)
    step2_preprocess_data(step1_out, step2_out, unique_json, show_progress)

    # [4] 二元模型（只依模型結果）
    bin_res, df_bin = dflare_binary_predict(
        input_csv=step2_out,
        binary_model_path=binary_model_path,
        output_csv=binary_csv,
        output_pie=binary_pie,
        output_bar=binary_bar,
        feat_cols=bin_feat_cols,
        show_progress=show_progress
    )

    # 只保留模型結果；如需全攻擊測試，可用 force_all_attack
    if force_all_attack:
        df_bin["is_attack"] = 1

    # 先寫回
    df_bin.to_csv(binary_csv, index=False, encoding="utf-8")

    # [5] 多元分級（僅攻擊流量；完全交給模型）
    df_attack = df_bin[df_bin['is_attack'] == 1].copy()
    if df_attack.empty:
        print(f"{Fore.YELLOW}{Style.BRIGHT}本批資料無攻擊流量（is_attack=1），跳過多元分級。")
        agg_stats = save_all_results_and_redraw(
            df_bin, batch_id, all_results_path, binary_pie, binary_bar,
            overwrite_all_results, dedupe_all_results,
        )
        bin_res["is_attack_distribution"] = {0: agg_stats.get("count_normal", 0), 1: agg_stats.get("count_attack", 0)}
        bin_res["count_all"] = int(agg_stats.get("count_all", 0))
        bin_res["count_attack"] = int(agg_stats.get("count_attack", 0))
        bin_res["count_normal"] = int(agg_stats.get("count_normal", 0))
        build_alerts(df_bin, alerts_json)

        # 沒有攻擊就不推播
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
            "all_multiclass_csv": all_multi_path,
            "multiclass_all_pie": multi_all_pie,
            "multiclass_all_bar": multi_all_bar,
            "discord_notify": {"action": "skip", "message_id": None, "reason": "no_attack"},
            "message": "本批無攻擊流量，已跳過多元分級",
        }

    # 有攻擊流量才進行多元分級（純模型）
    multi_res, df_attack = dflare_multiclass_predict(
        df_attack=df_attack,
        multiclass_model_path=multiclass_model_path,
        output_csv=multi_csv,
        output_pie=multi_pie,
        output_bar=multi_bar,
        feat_cols=multi_feat_cols,
        show_progress=show_progress
    )

    # 把 Severity 回寫到 df_bin（僅 is_attack==1）
    df_bin.loc[df_attack.index, "Severity"] = df_attack["Severity"].values
    df_bin.to_csv(binary_csv, index=False, encoding="utf-8")

    # [6] 累積輸出與重繪（非阻塞版）
    agg_stats = save_all_results_and_redraw(
        df_bin, batch_id, all_results_path, binary_pie, binary_bar,
        overwrite_all_results, dedupe_all_results,
    )
    bin_res["is_attack_distribution"] = {0: agg_stats.get("count_normal", 0), 1: agg_stats.get("count_attack", 0)}
    bin_res["count_all"] = int(agg_stats.get("count_all", 0))
    bin_res["count_attack"] = int(agg_stats.get("count_attack", 0))
    bin_res["count_normal"] = int(agg_stats.get("count_normal", 0))

    multi_stats = save_all_multiclass_results_and_redraw(
        df_attack_with_sev=df_attack,
        batch_id=batch_id,
        all_multi_path=all_multi_path,
        multi_all_pie=multi_all_pie,
        multi_all_bar=multi_all_bar,
        overwrite=overwrite_all_results,
        dedupe=dedupe_all_results,
    )
    multi_res["severity_distribution"] = {int(k): int(v) for k, v in multi_stats.get("severity_distribution", {}).items()}
    multi_res["count_all"] = int(multi_stats.get("count_all", 0))

    # [7] 告警彙整
    build_alerts(df_bin, alerts_json)

    # [8] Discord 去重推播（可選；非阻塞策略）
    discord_info = {"action": "skip", "message_id": None}
    if discord_webhook_url:
        try:
            discord_info = notify_discord_dedup(
                df_attack=df_attack,
                webhook_url=discord_webhook_url,
                state_path=discord_state_json,
                batch_id=batch_id,
                dedup_sec=notify_dedup_sec,
                growth_ratio=notify_growth_ratio,
                update_instead=True,
                only_once_update=True,
            )
        except Exception as e:
            print(f"{Fore.YELLOW}Discord 推播例外：{e}")

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
        "all_multiclass_csv": all_multi_path,
        "multiclass_all_pie": multi_all_pie,
        "multiclass_all_bar": multi_all_bar,
        "discord_notify": discord_info,
    }

# ---------- 告警彙整 ----------

def build_alerts(df: pd.DataFrame, out_json: str):
    df = _normalize_columns(df)
    out = {}
    vc = df.loc[df["is_attack"] == 1, "crlevel"].value_counts(dropna=False).to_dict()
    out["attack_crlevel_distribution"] = {str(k): int(v) for k, v in vc.items()}
    vt = df.loc[df["is_attack"] == 1, "attack_type"].value_counts().to_dict()
    out["attack_type_distribution"] = {str(k): int(v) for k, v in vt.items()}
    vd = df.loc[df["is_attack"] == 1, "direction"].value_counts().head(10).to_dict()
    out["top_directions"] = vd
    # 新增：Severity 分布（僅攻擊流量，若有）
    if "Severity" in df.columns:
        vs = df.loc[df["is_attack"] == 1, "Severity"].value_counts().sort_index().to_dict()
        out["severity_distribution"] = {str(k): int(v) for k, v in vs.items()}
    # 欄位兼容
    src_col = "SourceIP" if "SourceIP" in df.columns else ("src_ip" if "src_ip" in df.columns else None)
    if src_col:
        vs = df.loc[df["is_attack"] == 1, src_col].value_counts().head(10).to_dict()
        out["top_source_ip"] = {str(k): int(v) for k, v in vs.items()}
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)

# ==== 取得新的 batch_id ====

def get_next_batch_id(all_results_path):
    if not os.path.exists(all_results_path):
        return 1
    try:
        df = pd.read_csv(all_results_path, usecols=["batch_id"])  # 只讀一欄，避免卡頓
        if "batch_id" in df.columns and not df.empty:
            return int(df["batch_id"].max()) + 1
        else:
            return 1
    except Exception:
        return 1

# ==================== CLI ====================

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="D-FLARE SYS 全流程自動批次工具（Cisco ASA 5506-X｜非阻塞穩定版）"
    )
    # 基本 I/O（必填，避免互動式阻塞）
    parser.add_argument('--raw_log', type=str, required=True, help='原始 log 檔（csv/txt/gz）')
    parser.add_argument('--bin_model', type=str, required=True, help='二元模型 .pkl')
    parser.add_argument('--multi_model', type=str, required=True, help='多元模型 .pkl')
    parser.add_argument('--output_dir', type=str, required=True, help='輸出目錄')

    # 選項
    parser.add_argument('--no_progress', action='store_true', help='關閉進度列（建議大量資料時開啟）')
    parser.add_argument('--force_all_attack', action='store_true', help='將本批全數視為攻擊（測試用）')
    parser.add_argument('--overwrite_all_results', action='store_true', help='覆寫累積 all_results.csv（不建議）')
    parser.add_argument('--dedupe_all_results', action='store_true', help='附加時去重複（大檔可能卡）')
    parser.add_argument('--whitelist', type=str, help='白名單檔（保留參數，程式中可自行接）')

    # Discord 去重推播
    parser.add_argument('--discord_webhook', type=str, help='Discord Webhook URL（可選：啟用去重推播）')
    parser.add_argument('--notify_dedup_sec', type=int, default=120, help='去重視窗秒數（預設 120）')
    parser.add_argument('--notify_growth_ratio', type=float, default=0.5, help='視窗內數量成長比例門檻（預設 0.5）')
    parser.add_argument('--notify_update_instead', action="store_true", help='滿足門檻時採用 PATCH 更新原訊息')
    parser.add_argument('--notify_min_interval_sec', type=int, default=5, help='同一簽章兩次更新最小間隔秒數（預設 5）')

    args = parser.parse_args()

    show_progress = not args.no_progress
    os.makedirs(args.output_dir, exist_ok=True)

    print(f"{Fore.CYAN}{Style.BRIGHT}🚦 啟動 D-FLARE SYS 全流程 Pipeline（非阻塞穩定版）...")
    t0 = time.time()
    result = dflare_sys_full_pipeline(
        raw_log_path=args.raw_log,
        binary_model_path=args.bin_model,
        multiclass_model_path=args.multi_model,
        output_dir=args.output_dir,
        bin_feat_cols=None,
        multi_feat_cols=None,
        show_progress=show_progress,
        force_all_attack=args.force_all_attack,
        overwrite_all_results=args.overwrite_all_results,
        dedupe_all_results=args.dedupe_all_results,
        whitelist_path=args.whitelist,
        discord_webhook_url=args.discord_webhook,
        notify_dedup_sec=args.notify_dedup_sec,
        notify_growth_ratio=args.notify_growth_ratio,
        notify_update_instead=args.notify_update_instead,
        notify_min_interval_sec=args.notify_min_interval_sec,
    )
    print(f"{Fore.GREEN}{Style.BRIGHT}🚀 全流程完成！結果已輸出至：{args.output_dir}")
    print(json.dumps(result, ensure_ascii=False, indent=2))
    print(f"{Fore.CYAN}{Style.BRIGHT}總耗時：{time.time() - t0:.1f} 秒。")
