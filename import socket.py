import socket
import os
import csv
import re
import time
from datetime import datetime

# === 設定 ===
HOST = '0.0.0.0'
PORT = 514  # ASA syslog 預設端口
SAVE_DIR = r"C:\Users\user\Desktop\asa_log"
BATCH_SIZE = 500000
SAVE_INTERVAL = 10  # 每幾秒寫入一次

os.makedirs(SAVE_DIR, exist_ok=True)

CSV_HEADER = ["Severity", "Date", "Time", "SyslogID",
              "SourceIP", "SourcePort", "DestinationIP", "DestinationPort",
              "Duration", "Bytes", "Protocol", "Action", "Description"]

# 為每一級維護一個 buffer 和 file index
all_logs = {level: [] for level in range(7)}
file_index = {level: 1 for level in range(7)}
last_save_time = time.time()

def get_protocol(desc):
    desc = desc.lower()
    if "tcp" in desc:
        return "TCP"
    elif "udp" in desc:
        return "UDP"
    elif "icmp" in desc:
        return "ICMP"
    elif "http" in desc and "https" not in desc:
        return "HTTP"
    elif "https" in desc:
        return "HTTPS"
    elif "dns" in desc:
        return "DNS"
    elif "scan" in desc:
        return "SCAN"
    elif "flood" in desc or "rate" in desc:
        return "FLOOD"
    else:
        return "Other"

def get_action(desc):
    desc = desc.lower()
    if "teardown" in desc:
        return "Teardown"
    elif "built" in desc:
        return "Built"
    elif "deny" in desc:
        return "Deny"
    elif "translation" in desc or "translated" in desc:
        return "Translation"
    elif "login" in desc:
        return "Login"
    elif "drop" in desc:
        return "Drop"
    else:
        return "Other"

def parse_log_line(raw_line):
    timestamp = datetime.now()
    date_str = timestamp.strftime("%Y-%m-%d")
    time_str = timestamp.strftime("%H:%M:%S")

    severity_match = re.search(r'%ASA-(\d)-(\d{6})', raw_line)
    if not severity_match:
        return None

    severity = int(severity_match.group(1))
    syslog_id = severity_match.group(2)

    ip_port_match = re.search(r'(\d{1,3}(?:\.\d{1,3}){3})/(\d+)\D+(\d{1,3}(?:\.\d{1,3}){3})/(\d+)', raw_line)
    if ip_port_match:
        src_ip = ip_port_match.group(1)
        src_port = ip_port_match.group(2)
        dst_ip = ip_port_match.group(3)
        dst_port = ip_port_match.group(4)
    else:
        src_ip = src_port = dst_ip = dst_port = ""

    duration_match = re.search(r'duration (\d+:\d+:\d+)', raw_line)
    duration = duration_match.group(1) if duration_match else ""

    bytes_match = re.search(r'bytes (\d+)', raw_line)
    byte_count = bytes_match.group(1) if bytes_match else ""

    desc = raw_line.strip()
    protocol = get_protocol(desc)
    action = get_action(desc)

    return [severity, date_str, time_str, syslog_id,
            src_ip, src_port, dst_ip, dst_port,
            duration, byte_count, protocol, action, desc]

def save_level_logs(level):
    """每級存自己的檔案。"""
    filename = f"asa_level{level}_{file_index[level]}.csv"
    path = os.path.join(SAVE_DIR, filename)
    with open(path, "w", newline='', encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(CSV_HEADER)
        writer.writerows(all_logs[level])
    print(f"💾 Level {level} log 已寫入：{filename}")

# === 接收 log ===
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((HOST, PORT))
print("✅ 正在接收 ASA syslog 並依等級分檔儲存到 CSV...")

try:
    while True:
        sock.settimeout(0.5)
        try:
            data, addr = sock.recvfrom(4096)
            raw_log = data.decode(errors='ignore')
            print(raw_log.strip())

            parsed = parse_log_line(raw_log)
            if not parsed:
                continue

            severity = parsed[0]
            if severity in all_logs:
                all_logs[severity].append(parsed)

                # 若超過 BATCH_SIZE，清空並進新檔名
                if len(all_logs[severity]) >= BATCH_SIZE:
                    save_level_logs(severity)
                    all_logs[severity].clear()
                    file_index[severity] += 1

        except socket.timeout:
            pass

        # 定時存檔（每 SAVE_INTERVAL 秒）
        if time.time() - last_save_time > SAVE_INTERVAL:
            for level in all_logs:
                if all_logs[level]:  # 有內容才存
                    save_level_logs(level)
            last_save_time = time.time()

except KeyboardInterrupt:
    print("\n🛑 停止程式，儲存剩餘資料...")
    for level in all_logs:
        if all_logs[level]:
            save_level_logs(level)
    sock.close()
    print("✅ 結束程式。")
