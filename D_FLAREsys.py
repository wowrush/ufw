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
import pandas as pd
from tqdm import tqdm
from colorama import init, Fore, Style

init(autoreset=True)

# ==== 取得新的 batch_id（從 all_results.csv 檔案自動遞增）====
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

# =============== STEP1：資料清洗 + 唯一值 ===============
def step1_process_logs(raw_log_path, step1_out_path, unique_out_json, batch_id, show_progress=True):
    STANDARD_COLUMNS = [
        "batch_id", "Datetime", "SyslogID", "Severity", "SourceIP", "SourcePort",
        "DestinationIP", "DestinationPort", "Duration", "Bytes",
        "Protocol", "Action", "Description", "raw_log"
    ]
    unique_vals = {col: set() for col in STANDARD_COLUMNS}
    CHUNK_SIZE = 50000

    def detect_encoding(file_path):
        import chardet
        with open(file_path, 'rb') as f:
            return chardet.detect(f.read(10000)).get('encoding', 'utf-8') or 'utf-8'

    print(f"{Fore.CYAN}{Style.BRIGHT}STEP1：開始資料清洗與唯一值統計")
    encoding = detect_encoding(raw_log_path)
    total_lines = sum(1 for _ in open(raw_log_path, encoding=encoding))
    processed_count = 0

    with open(raw_log_path, "r", encoding=encoding, errors="replace") as f, \
         open(step1_out_path, "w", newline='', encoding="utf-8") as out_f:
        reader = csv.DictReader(f)
        writer = csv.DictWriter(out_f, fieldnames=STANDARD_COLUMNS)
        writer.writeheader()
        pbar = tqdm(reader, total=total_lines-1, desc=f"{Fore.CYAN}清洗進度", disable=not show_progress)
        for i, row in enumerate(pbar):
            record = {col: row.get(col, "") for col in STANDARD_COLUMNS if col != "batch_id" and col != "raw_log"}
            record["batch_id"] = batch_id
            record["raw_log"] = json.dumps(row, ensure_ascii=False)
            # 補齊空欄
            for col in STANDARD_COLUMNS:
                if col not in record:
                    record[col] = "unknown"
                unique_vals[col].add(record[col])
            writer.writerow(record)
            processed_count += 1
            if (i+1) % 10000 == 0:
                pbar.set_postfix_str(f"{Fore.YELLOW}已處理 {i+1} 筆，唯一值累計：{ {k: len(v) for k, v in unique_vals.items()} }")
            if (i+1) % CHUNK_SIZE == 0:
                out_f.flush()
        print(f"{Fore.GREEN}{Style.BRIGHT}STEP1 結束，共處理 {processed_count} 筆資料。")

    unique_json = {k: sorted(list(v)) for k, v in unique_vals.items()}
    with open(unique_out_json, "w", encoding="utf-8") as f:
        json.dump(unique_json, f, ensure_ascii=False, indent=4)
    print(f"{Fore.GREEN}{Style.BRIGHT}STEP1 完成：已輸出 {step1_out_path} 及 {unique_out_json}")
# =============== STEP2：資料預處理 ===============
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

    def is_attack_severity(x):
        try:
            return 1 if int(str(x).strip()) <= 4 else 0
        except Exception:
            return 0

    for chunk in tqdm(pd.read_csv(step1_out_path, chunksize=CHUNK_SIZE), desc=f"{Fore.CYAN}預處理進度", disable=not show_progress, total=total//CHUNK_SIZE+1):
        # 欄位映射/型態補齊
        for col, mapping in CATEGORICAL_MAPPINGS.items():
            if col in chunk.columns:
                chunk[col] = chunk[col].astype(str).str.lower().map(mapping).fillna(-1).astype(int)
        # is_attack（修正：用 int+strip 防呆）
        if "Severity" in chunk.columns:
            chunk["is_attack"] = chunk["Severity"].apply(is_attack_severity)
        else:
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
    import joblib
    from matplotlib.ticker import MaxNLocator
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
    pie_colors = ["#ff9800", "#888888"]

    tqdm.write(f"{Fore.CYAN}{Style.BRIGHT}STEP3-1：載入預處理資料與二元模型...")
    df = pd.read_csv(input_csv, encoding="utf-8")
    bin_model = joblib.load(binary_model_path)

    # 特徵欄位自動對齊（只取模型訓練過的欄位，batch_id自動排除）

    if hasattr(bin_model, "feature_names_in_"):
        model_feat_cols = list(bin_model.feature_names_in_)
    elif feat_cols is not None:
        model_feat_cols = feat_cols
    else:
        raise RuntimeError("二元模型未存特徵名稱，請明確指定 feat_cols。")
    # 只保留模型需要的欄位，不多不少，不會有 batch_id
    df_model = df.reindex(columns=model_feat_cols, fill_value=-1)
    df_model = df_model.fillna(-1).astype(int)

    tqdm.write(f"{Fore.CYAN}{Style.BRIGHT}STEP3-1：二元模型預測與圖表產生中...")
    df['is_attack'] = bin_model.predict(df_model)
    df.to_csv(output_csv, index=False, encoding="utf-8")
    tqdm.write(f"{Fore.GREEN}{Style.BRIGHT}STEP3-1：二元判斷已輸出 {output_csv}")

    # 繪圖：is_attack 分布
    is_attack_dist = df['is_attack'].value_counts().sort_index().reindex([0, 1], fill_value=0)
    labels_attack = ['正常流量', '攻擊流量']
    pie_base_colors = ["#04ff11", "#FF0000"]  # 正常、攻擊

    # 圓餅圖
    
    nonzero_idx = [i for i, v in enumerate(is_attack_dist) if v > 0]
    pie_values = [is_attack_dist.iloc[i] for i in nonzero_idx]
    pie_labels = [labels_attack[i] for i in nonzero_idx]
    pie_colors = [pie_base_colors[i] for i in nonzero_idx]
    plt.figure(figsize=(6, 6))
    if len(pie_values) == 0:
        plt.text(0.5, 0.5, '無資料', fontsize=20, ha='center', va='center')
        plt.axis('off')
    elif len(pie_values) == 1:
        plt.pie(
            [1], labels=[pie_labels[0]], colors=[pie_colors[0]],
            autopct='lambda', textprops={'fontsize': 16},
            startangle=90, wedgeprops={'edgecolor': 'white', 'linewidth': 2}
        )
    else:
        plt.pie(
            pie_values, labels=pie_labels,
            autopct=lambda pct: ('%1.1f%%' % pct) if pct > 0 else '',
            colors=pie_colors, textprops={'fontsize': 16},
            startangle=90, wedgeprops={'edgecolor': 'white', 'linewidth': 2}
        )
    plt.title("攻擊與正常流量比例（二元）", fontsize=18, pad=20)
    plt.tight_layout()
    plt.savefig(output_pie, bbox_inches='tight')
    plt.close()

    # 長條圖
    plt.figure(figsize=(7, 5))
    ax = plt.gca()
    ax.yaxis.set_major_locator(MaxNLocator(integer=True))
    plt.bar(labels_attack, is_attack_dist, color=pie_base_colors, edgecolor="#333", width=0.6)
    plt.xlabel('流量類型', fontsize=15, labelpad=10)
    plt.ylabel('數量', fontsize=15, labelpad=10)
    plt.title('攻擊與正常流量數量分布（二元）', fontsize=18, pad=20)
    for idx, v in enumerate(is_attack_dist):
        plt.text(idx, v + 0.05, str(v), ha='center', va='bottom', fontsize=15)
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
    import joblib
    from matplotlib.ticker import MaxNLocator
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

    # 只針對攻擊流量 Severity 分布
    sev_dist = df_attack['Severity'].value_counts().sort_index().reindex(show_levels, fill_value=0)
    sev_labels = [severity_map[i] for i in show_levels]
    colors_sev = ["#d32f2f", "#f57c08", "#fbc02d", "#04ff11"]
    
    # 圓餅圖
    nonzero_idx = [i for i, v in enumerate(sev_dist) if v > 0]
    pie_values = [sev_dist.iloc[i] for i in nonzero_idx]
    pie_labels = [sev_labels[i] for i in nonzero_idx]
    pie_colors = [colors_sev[i] for i in nonzero_idx]
    plt.figure(figsize=(6, 6))
    if len(pie_values) == 0:
        plt.text(0.5, 0.5, '無攻擊流量', fontsize=20, ha='center', va='center')
        plt.axis('off')
    elif len(pie_values) == 1:
        plt.pie(
            [1], labels=[pie_labels[0]], colors=[pie_colors[0]],
            autopct='lambda', textprops={'fontsize': 16},
            startangle=90, wedgeprops={'edgecolor': 'white', 'linewidth': 2}
        )
    else:
        plt.pie(
            pie_values, labels=pie_labels,
            autopct=lambda pct: ('%1.1f%%' % pct) if pct > 0 else '',
            colors=pie_colors, textprops={'fontsize': 16},
            startangle=90, wedgeprops={'edgecolor': 'white', 'linewidth': 2}
        )
    plt.title("Severity 分布（僅針對攻擊流量）", fontsize=18, pad=20)
    plt.tight_layout()
    plt.savefig(output_pie, bbox_inches='tight')
    plt.close()

    # 長條圖（所有標籤全出現，0 也要畫出 bar）
    plt.figure(figsize=(7, 5))
    ax = plt.gca()
    ax.yaxis.set_major_locator(MaxNLocator(integer=True))
    plt.bar(sev_labels, sev_dist, color=colors_sev, edgecolor="#333", width=0.6)
    plt.xlabel('Severity 等級（4為最低，1為最高）', fontsize=15, labelpad=10)
    plt.ylabel('數量', fontsize=15, labelpad=10)
    plt.title('Severity 分布（僅針對攻擊流量）', fontsize=18, pad=20)
    for idx, v in enumerate(sev_dist):
        plt.text(idx, v + 0.05, str(v), ha='center', va='bottom', fontsize=15)
    plt.tight_layout()
    plt.savefig(output_bar, bbox_inches='tight')
    plt.close()
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
    bin_feat_cols=None, multi_feat_cols=None, show_progress=True
):
    os.makedirs(output_dir, exist_ok=True)

    # ====== [1] 批次流水號取得（每一批唯一） ======
    all_results_path = os.path.join(output_dir, all_results_csv)
    batch_id = get_next_batch_id(all_results_path)

    # ====== [2] 每批暫存檔案（覆蓋即可，不做歷史保留） ======
    step1_out = os.path.join(output_dir, "processed_logs.csv")
    unique_json = os.path.join(output_dir, "log_unique_values.json")
    step2_out = os.path.join(output_dir, "preprocessed_data.csv")
    binary_csv = os.path.join(output_dir, "binary_result.csv")
    binary_pie = os.path.join(output_dir, "binary_pie.png")
    binary_bar = os.path.join(output_dir, "binary_bar.png")
    multi_csv = os.path.join(output_dir, "multiclass_result.csv")
    multi_pie = os.path.join(output_dir, "multiclass_pie.png")
    multi_bar = os.path.join(output_dir, "multiclass_bar.png")

    # ====== [3] ETL Pipeline ======
    step1_process_logs(raw_log_path, step1_out, unique_json, batch_id, show_progress)
    step2_preprocess_data(step1_out, step2_out, unique_json, show_progress)

    # ====== [4] 二元模型（全資料預測） ======
    bin_res, df_bin = dflare_binary_predict(
        input_csv=step2_out,
        binary_model_path=binary_model_path,
        output_csv=binary_csv,
        output_pie=binary_pie,
        output_bar=binary_bar,
        feat_cols=bin_feat_cols,
        show_progress=show_progress
    )

    # ====== [5] 多元模型（僅攻擊流量預測） ======
    df_bin["is_attack"] = pd.to_numeric(df_bin["is_attack"], errors="coerce").fillna(0).astype(int)
    df_attack = df_bin[df_bin['is_attack'] == 1].copy()
    if df_attack.empty:
        print(f"{Fore.YELLOW}{Style.BRIGHT}本批資料無攻擊流量（is_attack=1），跳過多元分級。")
        # 直接 append 到 all_results.csv
        write_header = not os.path.exists(all_results_path)
        df_bin["batch_id"] = batch_id
        with open(all_results_path, "a", newline='', encoding="utf-8") as allf:
            df_bin.to_csv(allf, header=write_header, index=False)
        return {
            "batch_id": batch_id,
            "binary": bin_res,
            "multiclass": None,
            "binary_output_csv": binary_csv,
            "binary_output_pie": binary_pie,
            "binary_output_bar": binary_bar,
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

    # ====== [6] APPEND 本批結果到 all_results.csv（僅追加，不覆蓋）======
    write_header = not os.path.exists(all_results_path)
    df_bin["batch_id"] = batch_id
    with open(all_results_path, "a", newline='', encoding="utf-8") as allf:
        df_bin.to_csv(allf, header=write_header, index=False)

    # ====== [7] 回傳所有 output 路徑，暫存僅保留最新，all_results 累積追蹤 ======
    return {
        "batch_id": batch_id,
        "binary": bin_res,
        "multiclass": multi_res,
        "binary_output_csv": binary_csv,
        "binary_output_pie": binary_pie,
        "binary_output_bar": binary_bar,
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
    args = parser.parse_args()

    # 用 tkinter 選檔 (互動)
    def pick_file(title="請選擇檔案", filetypes=[("所有檔案", "*.*")]):
        root = tk.Tk()
        root.withdraw()
        file_path = filedialog.askopenfilename(title=title, filetypes=filetypes)
        root.destroy()
        return file_path

    def pick_folder(title="請選擇資料夾"):
        root = tk.Tk()
        root.withdraw()
        folder_path = filedialog.askdirectory(title=title)
        root.destroy()
        return folder_path

    # 檢查參數，若沒指定就互動選擇
    raw_log = args.raw_log or pick_file("請選擇原始 log 檔", [("CSV", "*.csv"), ("文字", "*.txt"), ("GZ", "*.gz"), ("所有檔案", "*.*")])
    bin_model = args.bin_model or pick_file("請選擇二元模型 .pkl 檔", [("Pickle", "*.pkl")])
    multi_model = args.multi_model or pick_file("請選擇多元模型 .pkl 檔", [("Pickle", "*.pkl")])
    output_dir = args.output_dir or pick_folder("請選擇輸出資料夾")
    show_progress = not args.no_progress

    print(f"{Fore.CYAN}{Style.BRIGHT}🚦 啟動 D-FLARE SYS 全流程 Pipeline（二元+多元，支援 batch_id 與 append）...")
    t0 = time.time()
    result = dflare_sys_full_pipeline(
        raw_log_path=raw_log,
        binary_model_path=bin_model,
        multiclass_model_path=multi_model,
        output_dir=output_dir,
        bin_feat_cols=None,
        multi_feat_cols=None,
        show_progress=show_progress
    )
    print(f"{Fore.GREEN}{Style.BRIGHT}🚀 全流程完成！結果已輸出至：{output_dir}")
    print(json.dumps(result, ensure_ascii=False, indent=2))
    print(f"{Fore.CYAN}{Style.BRIGHT}總耗時：{time.time() - t0:.1f} 秒。")
