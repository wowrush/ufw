import sys
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding='utf-8')
import os
import json
import requests
import locale
import time
import pandas as pd
from datetime import datetime

os.environ["QT_AUTO_SCREEN_SCALE_FACTOR"] = "1"

# ===== PyQt5 相關匯入（一次匯入全部常用元件）=====
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QTextEdit, QComboBox, QLineEdit, QFileDialog,
    QSystemTrayIcon, QMenu, QAction, QCheckBox, QMessageBox, QGroupBox,
    QFormLayout, QSpinBox, QGridLayout,
    QListWidget, QListWidgetItem, QStackedWidget
)
from PyQt5.QtGui import QIcon, QColor, QPixmap, QFont, QPainter
from PyQt5.QtCore import Qt, QTimer, QProcess, QFileSystemWatcher, pyqtSignal, QThread


SETTINGS_FILE = "notifier_settings.txt"
USER_FILE = "line_users.txt"
LAST_USER_FILE = "last_user.txt"
LOGFETCHER_SETTINGS_FILE = "logfetcher_settings.json"

# --- 實用 function：可放主檔案最前面（只需一份）
def send_discord_alert(webhook_url, content):
    try:
        resp = requests.post(webhook_url, json={"content": content})
        return resp.status_code == 204
    except Exception as e:
        print(f"發送 Discord 通知失敗: {e}")
        return False


class AutoCleanWorker(QThread):
    """Run heavy cleaning/model tasks in background to keep UI responsive."""

    finished = pyqtSignal(dict)
    error = pyqtSignal(str)

    def __init__(self, binary_model_path, model_path, latest_file, output_dir):
        super().__init__()
        self.binary_model_path = binary_model_path
        self.model_path = model_path
        self.latest_file = latest_file
        self.output_dir = output_dir

    def run(self):
        import importlib.util
        import sys
        try:
            spec = importlib.util.spec_from_file_location("D_FLAREsys", "./D_FLAREsys.py")
            module = importlib.util.module_from_spec(spec)
            sys.modules["D_FLAREsys"] = module
            spec.loader.exec_module(module)
            result = module.dflare_sys_full_pipeline(
                raw_log_path=self.latest_file,
                binary_model_path=self.binary_model_path,
                multiclass_model_path=self.model_path,
                output_dir=self.output_dir,
                show_progress=False,
            )
            self.finished.emit(result)
        except Exception as e:
            self.error.emit(str(e))

class LogFetcherWidget(QWidget):
    """
    防火牆 log 擷取、自動監控、資料夾/檔案輪詢、自動清洗、流程回饋的主 UI 元件。
    支援自動儲存/載入使用者設定
    """

    def __init__(self, notifier_widget=None):
        super().__init__()
        # ==== 關聯外部通知元件 ====
        self.notifier_widget = notifier_widget

        # =========== 狀態欄位 ===========
        self.socket_proc = None       # log 擷取子程序
        self.processed_files = set()  # 已處理紀錄：(filepath, filesize, timestamp)
        self.last_file_checked = ""   # 上次輪詢檔案
        self.last_file_size = 0
        self.file_stable_count = 0    # 檔案穩定次數
        self.last_processed_file = "" # 上次實際自動分析的檔案
        self.watched_file = ""        # 監控中特定檔案
        self.listening = False        # 是否監聽狀態
        self.notified_multiclass_files = set()
        # =========== UI 設計 ===========
        layout = QVBoxLayout()
        title = QLabel("Log 擷取模組")
        title.setStyleSheet("font-size: 15pt; font-weight: bold; font-family: 'PingFang TC', 'Open Sans';")
        layout.addWidget(title)

        group = QGroupBox("⚡擷取設定")
        form = QFormLayout()

        self.start_btn = QPushButton("啟動監聽")
        self.start_btn.clicked.connect(self.start_listening)
        form.addRow("✅ 開始接收 ASA log：", self.start_btn)

        self.stop_btn = QPushButton("停止監聽")
        self.stop_btn.clicked.connect(self.stop_listening)
        form.addRow("⛔ 停止接收 ASA log：", self.stop_btn)

        self.status_label = QLabel("未啟動")
        form.addRow("📡 目前狀態：", self.status_label)

        self.save_dir_input = QLineEdit()
        self.save_dir_input.setPlaceholderText("請選擇 log 儲存資料夾")
        self.browse_btn = QPushButton("選擇路徑")
        self.browse_btn.clicked.connect(self.choose_save_dir)
        dir_layout = QHBoxLayout()
        dir_layout.addWidget(self.save_dir_input)
        dir_layout.addWidget(self.browse_btn)
        form.addRow("📁 log 儲存路徑：", dir_layout)

        # 二元模型
        self.binary_model_path_input = QLineEdit()
        self.binary_model_path_input.setPlaceholderText("請選擇二元模型檔（.pkl）")
        self.binary_model_btn = QPushButton("選擇模型")
        self.binary_model_btn.clicked.connect(self.choose_binary_model_path)
        binary_model_layout = QHBoxLayout()
        binary_model_layout.addWidget(self.binary_model_path_input)
        binary_model_layout.addWidget(self.binary_model_btn)
        form.addRow("🤖 二元模型檔案路徑：", binary_model_layout)

        # 多元模型
        self.model_path_input = QLineEdit()
        self.model_path_input.setPlaceholderText("請選擇多分類模型檔（.pkl）")
        self.model_btn = QPushButton("選擇模型")
        self.model_btn.clicked.connect(self.choose_model_path)
        model_layout = QHBoxLayout()
        model_layout.addWidget(self.model_path_input)
        model_layout.addWidget(self.model_btn)
        form.addRow("🤖 多元模型檔案路徑：", model_layout)

        # 清洗後 CSV
        self.clean_csv_dir_input = QLineEdit()
        self.clean_csv_dir_input.setPlaceholderText("請選擇資料清洗後 CSV 資料夾")
        self.clean_csv_browse_btn = QPushButton("選擇路徑")
        self.clean_csv_browse_btn.clicked.connect(self.choose_clean_csv_dir)
        clean_csv_layout = QHBoxLayout()
        clean_csv_layout.addWidget(self.clean_csv_dir_input)
        clean_csv_layout.addWidget(self.clean_csv_browse_btn)
        form.addRow("🧹 清洗後 CSV 放置位置：", clean_csv_layout)

        group.setLayout(form)
        layout.addWidget(group)

        # log 輸出區
        self.log_output = QTextEdit()
        self.log_output.setPlaceholderText("Log 顯示區 / 執行狀態回饋")
        layout.addWidget(self.log_output)
        self.setLayout(layout)

        # =========== 資料夾監控與 timer ===========
        self.folder_watcher = QFileSystemWatcher()
        self.folder_watcher.directoryChanged.connect(self.on_dir_changed)
        self.auto_clean_timer = QTimer()
        self.auto_clean_timer.setSingleShot(True)
        self.auto_clean_timer.timeout.connect(self.run_auto_cleaning)
        self.poll_timer = QTimer()
        self.poll_timer.timeout.connect(self.poll_latest_file)

        # ======= 載入儲存設定 =======
        self.load_settings()
        self.log_output.append("[啟動] LogFetcherWidget 初始化完成")

    # ====== 設定檔 load/save ======
    def load_settings(self):
        if os.path.exists(LOGFETCHER_SETTINGS_FILE):
            try:
                with open(LOGFETCHER_SETTINGS_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self.save_dir_input.setText(data.get("save_dir", ""))
                    self.binary_model_path_input.setText(data.get("binary_model_path", ""))
                    self.model_path_input.setText(data.get("model_path", ""))
                    self.clean_csv_dir_input.setText(data.get("clean_csv_dir", ""))
            except Exception:
                pass

    def save_settings(self):
        data = {
            "save_dir": self.save_dir_input.text().strip(),
            "binary_model_path": self.binary_model_path_input.text().strip(),
            "model_path": self.model_path_input.text().strip(),
            "clean_csv_dir": self.clean_csv_dir_input.text().strip()
        }
        try:
            with open(LOGFETCHER_SETTINGS_FILE, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            self.log_output.append("✅ Log 擷取設定已儲存")
        except Exception as e:
            self.log_output.append(f"❌ Log 設定儲存失敗: {e}")

    # ================= 選擇路徑/模型 =================
    def choose_save_dir(self):
        folder = QFileDialog.getExistingDirectory(self, "選擇資料夾")
        if folder:
            self.save_dir_input.setText(folder)
            try:
                self.folder_watcher.removePaths(self.folder_watcher.directories())
                self.folder_watcher.removePaths(self.folder_watcher.files())
            except Exception as e:
                self.log_output.append(f"[Watcher] 清空時例外：{e}")
            try:
                self.folder_watcher.addPath(folder)
                self.log_output.append(f"🔎 監控資料夾：{folder}")
            except Exception as e:
                self.log_output.append(f"[Watcher] 無法監控路徑：{e}")
            self.save_settings()

    def choose_binary_model_path(self):
        path, _ = QFileDialog.getOpenFileName(self, "選擇二元模型檔", "", "PKL Files (*.pkl);;All Files (*)")
        if path:
            self.binary_model_path_input.setText(path)
            self.save_settings()

    def choose_model_path(self):
        path, _ = QFileDialog.getOpenFileName(self, "選擇多元模型檔", "", "PKL Files (*.pkl);;All Files (*)")
        if path:
            self.model_path_input.setText(path)
            self.save_settings()

    def choose_clean_csv_dir(self):
        folder = QFileDialog.getExistingDirectory(self, "選擇清洗後 CSV 資料夾")
        if folder:
            self.clean_csv_dir_input.setText(folder)
            self.save_settings()
    # ================= 啟動/停止監聽 =================
    def start_listening(self):
        if self.listening:
            self.log_output.append("⚠️ 已在監聽狀態，不重複啟動")
            return

        save_path = self.save_dir_input.text().strip()
        binary_model_path = self.binary_model_path_input.text().strip()
        model_path = self.model_path_input.text().strip()
        clean_csv_dir = self.clean_csv_dir_input.text().strip()

        missing = []
        if not save_path:
            missing.append("log 儲存資料夾")
        if not binary_model_path:
            missing.append("二元模型檔（.pkl）")
        if not model_path:
            missing.append("多分類模型檔（.pkl）")
        if not clean_csv_dir:
            missing.append("清洗後 CSV 放置資料夾")
        if missing:
            QMessageBox.warning(self, "缺少必要設定", f"請確認已選擇：\n" + "\n".join(missing) + "\n\n四項皆需設定才能啟動監聽！")
            self.log_output.append(f"❗ 缺少必要設定：{'、'.join(missing)}")
            return

        # 檢查目錄權限
        if not os.path.exists(save_path):
            self.log_output.append(f"❌ 路徑不存在：{save_path}")
            return
        if not os.access(save_path, os.W_OK):
            self.log_output.append(f"❌ 路徑無法寫入：{save_path}")
            return

        # ===== 啟動 socket_5.py 子程序（僅啟動一次） =====
        self.socket_proc = QProcess()
        self.socket_proc.setProgram(sys.executable)
        self.socket_proc.setArguments(["socket_5.py", save_path])
        self.socket_proc.setProcessChannelMode(QProcess.MergedChannels)
        self.socket_proc.finished.connect(self.clean_finished)
        self.socket_proc.readyReadStandardOutput.connect(self.handle_log_output)
        self.socket_proc.readyReadStandardError.connect(self.handle_log_output)
        self.socket_proc.start()

        # ===== 設定監聽狀態與 timer 啟動 =====
        self.listening = True
        self.status_label.setText("✅ 監聽中...")
        self.log_output.append(f"🟢 已啟動 log 擷取，儲存位置：{save_path}")
        try:
            if save_path not in self.folder_watcher.directories():
                self.folder_watcher.addPath(save_path)
        except Exception as e:
            self.log_output.append(f"[Watcher] 監控路徑失敗：{e}")

        self.poll_timer.start(5000)

    def stop_listening(self):
        if not self.listening:
            self.log_output.append("⚠️ 尚未啟動監聽")
            return

        if self.socket_proc:
            try:
                self.socket_proc.kill()
                self.log_output.append("🛑 已停止 import socket_5.py")
            except Exception as e:
                self.log_output.append(f"🛑 子程序停止例外：{e}")
            self.socket_proc = None

        self.poll_timer.stop()
        self.auto_clean_timer.stop()
        try:
            self.folder_watcher.removePaths(self.folder_watcher.directories())
            self.folder_watcher.removePaths(self.folder_watcher.files())
        except Exception as e:
            self.log_output.append(f"[Watcher] 停止監控例外：{e}")

        self.status_label.setText("⛔ 已停止")
        self.listening = False
        self.log_output.append("[停止] 監聽狀態已關閉")

    # ================= 資料夾/檔案監控 =================
    def on_dir_changed(self, path):
        if not self.listening:
            self.log_output.append("[Watcher] 目錄變化觸發，但尚未啟動監聽，忽略事件")
            return

        self.log_output.append(f"[Watcher] 目錄變化觸發：{path}")
        try:
            files = [f for f in os.listdir(path)
                     if f.endswith(".csv") and f.startswith("asa_logs_") and "_result" not in f]
        except Exception as e:
            self.log_output.append(f"[Watcher] 讀取資料夾失敗：{e}")
            return

        if not files:
            self.log_output.append("[Watcher] 找不到任何有效 log 檔")
            return

        files.sort(key=lambda x: os.path.getmtime(os.path.join(path, x)), reverse=True)
        latest_file = os.path.join(path, files[0])

        if latest_file != self.last_processed_file:
            self.last_processed_file = latest_file
            self.log_output.append(f"🆕 偵測到新 log 檔案：{latest_file}，即將自動分析")
            self.auto_clean_timer.start(1000)

    def poll_latest_file(self):
        if not self.listening:
            return

        folder = self.save_dir_input.text().strip()
        self.log_output.append(f"[輪詢] 開始掃描資料夾：{folder}")
        if not folder or not os.path.exists(folder):
            self.log_output.append("[輪詢] 資料夾無效或不存在")
            return

        try:
            files = [f for f in os.listdir(folder)
                     if f.endswith(".csv") and f.startswith("asa_logs_") and "_result" not in f]
        except Exception as e:
            self.log_output.append(f"[輪詢] 無法讀取資料夾：{e}")
            return

        if not files:
            self.log_output.append("[輪詢] 無 log 檔案")
            return

        files.sort(key=lambda x: os.path.getmtime(os.path.join(folder, x)), reverse=True)
        latest_file = os.path.join(folder, files[0])
        curr_size = os.path.getsize(latest_file) if os.path.exists(latest_file) else 0

        now = time.time()
        max_age = 3600
        self.processed_files = {(f, size, t) for (f, size, t) in self.processed_files if now - t < max_age}

        already_processed = any(f == latest_file and size == curr_size for (f, size, t) in self.processed_files)
        if already_processed:
            self.log_output.append(f"[輪詢] 已處理過：{latest_file}，跳過")
            return

        if latest_file != self.last_file_checked:
            self.last_file_checked = latest_file
            self.last_file_size = curr_size
            self.file_stable_count = 1
            self.log_output.append(f"[輪詢] 新檔案檢查: {latest_file}, 檔案大小: {curr_size}")
            return

        if curr_size == self.last_file_size:
            self.file_stable_count += 1
            self.log_output.append(f"[輪詢] 檔案大小穩定 ({self.file_stable_count} 次): {curr_size}")
        else:
            self.file_stable_count = 1
            self.log_output.append(f"[輪詢] 檔案大小變動: {curr_size}（前次: {self.last_file_size}），重新計數")
            self.last_file_size = curr_size

        if self.file_stable_count >= 2:
            self.last_processed_file = latest_file
            self.log_output.append(f"🆕 [輪詢] 偵測到新 log 檔案穩定：{latest_file}，即將自動分析")
            self.auto_clean_timer.start(1000)
            self.processed_files.add((latest_file, curr_size, now))

    # ================= 自動清洗分析流程 =================
    def run_auto_cleaning(self):
        import traceback

        # 1. 收集必要路徑
        binary_model_path = self.binary_model_path_input.text().strip()
        model_path = self.model_path_input.text().strip()
        latest_file = self.last_processed_file
        output_dir = self.clean_csv_dir_input.text().strip()

        self.log_output.append("========[Debug 檢查路徑]========")
        self.log_output.append(f"二元模型路徑：{binary_model_path}")
        self.log_output.append(f"多元模型路徑：{model_path}")
        self.log_output.append(f"log檔路徑：{latest_file}")
        self.log_output.append(f"清洗輸出路徑：{output_dir}")
        self.log_output.append("================================")

        missing = []
        if not binary_model_path:
            missing.append("二元模型檔案")
        if not model_path:
            missing.append("多分類模型檔案")
        if not latest_file or not os.path.exists(latest_file):
            missing.append("log 檔案")
        if not output_dir:
            missing.append("清洗後 CSV 存放資料夾")
        if missing:
            self.log_output.append(f"❗ 缺少：{'、'.join(missing)}，無法自動分析！")
            return

        # 3. 使用背景執行緒處理耗時流程，避免凍結 UI
        self._current_clean_file = latest_file
        self.clean_thread = AutoCleanWorker(binary_model_path, model_path, latest_file, output_dir)
        self.clean_thread.finished.connect(self.on_clean_finished)
        self.clean_thread.error.connect(lambda msg: self.log_output.append(f"❌ 自動分析失敗：{msg}"))
        self.clean_thread.start()

    def on_clean_finished(self, result):
        try:
            self.log_output.append(f"✅ 自動分析完成！結果：{result['binary']['output_csv']}")
            self.log_output.append(f"📊 圓餅圖（is_attack）：{result['binary'].get('output_pie', '-')}")
            self.log_output.append(f"📊 長條圖（is_attack）：{result['binary'].get('output_bar', '-')}")
            multiclass = result.get('multiclass')
            output_csv = multiclass.get('output_csv') if multiclass else None
            if multiclass and output_csv and os.path.exists(output_csv):
                if output_csv in self.notified_multiclass_files:
                    self.log_output.append(f"（{output_csv} 已推播過，略過重複通知）")
                    return
                self.log_output.append(f"📊 圓餅圖（Severity）：{multiclass.get('output_pie', '-')}")
                self.log_output.append(f"📊 長條圖（Severity）：{multiclass.get('output_bar', '-')}")
                try:
                    df = pd.read_csv(output_csv)
                    if "Severity" in df.columns:
                        sev = pd.to_numeric(df["Severity"], errors="coerce").fillna(0).astype(int)
                        if (sev.isin([1,2,3]).any()):
                            self.log_output.append("📣 已自動呼叫通知模組進行推播 ...")
                            try:
                                self.notifier_widget.trigger_notification(output_csv)
                                self.log_output.append("✅ 通知推播呼叫完成")
                                self.notified_multiclass_files.add(output_csv)
                            except Exception as e:
                                self.log_output.append(f"❌ 通知推播失敗：{e}")
                        else:
                            self.log_output.append("（本批次無高風險流量，未自動推播）")
                    else:
                        self.log_output.append("（多元結果檔不含 Severity 欄，未自動推播）")
                except Exception as e:
                    self.log_output.append(f"❌ 多元結果檢查失敗：{e}")
            else:
                self.log_output.append("（本批次無攻擊流量，未產生多元分級圖表，未自動推播）")
            self.processed_files = {pf for pf in self.processed_files if pf[0] != self._current_clean_file}
        except Exception as e:
            self.log_output.append(f"❌ 自動分析失敗：{e}")
            self.log_output.append(traceback.format_exc())

    def handle_log_output(self):

        if not self.socket_proc:
            return
        while self.socket_proc.canReadLine():
            raw = bytes(self.socket_proc.readLine())
            line = None
            for enc in (locale.getpreferredencoding(False), "utf-8", "cp950"):
                try:
                    line = raw.decode(enc).strip()
                    break
                except UnicodeDecodeError:
                    continue
            if line is None:
                line = raw.decode("utf-8", errors="ignore").strip()
            line = "".join(ch for ch in line if ch.isprintable())
            if line:
                self.log_output.append(line)

    def clean_finished(self):
        self.log_output.append("🧹 清洗程序已結束")
        # 依需求可加 reset 或通知 UI
class NotifierWidget(QWidget):
    """D-FLARE 通知設定與推播模組（強化 LINE Bot 欄位與自動儲存）"""
    def __init__(self):
        super().__init__()
        self.settings = {
            "gemini_api_key": "",
            "line_channel_secret": "",
            "line_channel_access_token": "",   # 新增：LINE Bot Access Token
            "line_webhook_url": "",
            "discord_webhook_url": ""
        }
        self.load_settings()

        # =========== UI 設計 ===========
        layout = QVBoxLayout()
        title = QLabel("通知模組")
        title.setStyleSheet("font-size: 15pt; font-weight: bold; font-family: 'PingFang TC', 'Open Sans';")
        layout.addWidget(title)

        config_group = QGroupBox("🔑 基本通知設定")
        config_form = QFormLayout()
        config_form.setLabelAlignment(Qt.AlignLeft | Qt.AlignVCenter)

        self.gemini_input = QLineEdit()
        self.gemini_input.setEchoMode(QLineEdit.Password)
        self.gemini_input.setText(self.settings["gemini_api_key"])
        config_form.addRow("🤖 Gemini API Key：", self.gemini_input)

        self.line_secret_input = QLineEdit()
        self.line_secret_input.setEchoMode(QLineEdit.Password)
        self.line_secret_input.setText(self.settings["line_channel_secret"])
        config_form.addRow("🟩 LINE Channel Secret：", self.line_secret_input)

        self.line_token_input = QLineEdit()
        self.line_token_input.setEchoMode(QLineEdit.Password)
        self.line_token_input.setText(self.settings["line_channel_access_token"])
        config_form.addRow("🔑 LINE Channel Access Token：", self.line_token_input)

        self.line_webhook_input = QLineEdit()
        self.line_webhook_input.setText(self.settings["line_webhook_url"])
        config_form.addRow("🌐 LINE Webhook URL：", self.line_webhook_input)

        self.discord_url_input = QLineEdit()
        self.discord_url_input.setText(self.settings["discord_webhook_url"])
        config_form.addRow("💬 Discord Webhook URL：", self.discord_url_input)

        self.save_btn = QPushButton("💾 儲存設定")
        self.save_btn.clicked.connect(self.save_settings)
        config_form.addRow("🔒 儲存所有設定：", self.save_btn)

        config_group.setLayout(config_form)
        layout.addWidget(config_group)

        # ====== 推播測試 ======
        notify_group = QGroupBox("🚀 推播測試")
        notify_layout = QHBoxLayout()
        self.line_button = QPushButton("🟩 發送 LINE 測試通知")
        self.discord_button = QPushButton("💬 發送 Discord 測試通知")
        notify_layout.addWidget(self.line_button)
        notify_layout.addSpacing(16)
        notify_layout.addWidget(self.discord_button)
        notify_group.setLayout(notify_layout)
        layout.addWidget(notify_group)

        self.webhook_status = QTextEdit()
        self.webhook_status.setPlaceholderText("🔔 狀態回饋 / 成功 / 失敗 / 提示")
        self.webhook_status.setStyleSheet("font-size: 11pt; font-family: 'PingFang TC', 'Open Sans';")
        layout.addWidget(self.webhook_status, stretch=1)
        self.setLayout(layout)
        self.setStyleSheet("""
            QGroupBox { margin-top: 20px; }
            QLineEdit { font-size: 12pt; }
            QPushButton { font-size: 11pt; min-width:140px; }
            QLabel { font-size: 11pt; }
        """)

        # 事件綁定
        self.line_button.clicked.connect(self.send_line_test)
        self.discord_button.clicked.connect(self.send_discord_test)

    def load_settings(self):
        if os.path.exists(SETTINGS_FILE):
            try:
                with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
                    self.settings = json.load(f)
            except Exception:
                pass

    def save_settings(self):
        self.settings["gemini_api_key"] = self.gemini_input.text().strip()
        self.settings["line_channel_secret"] = self.line_secret_input.text().strip()
        self.settings["line_channel_access_token"] = self.line_token_input.text().strip()
        self.settings["line_webhook_url"] = self.line_webhook_input.text().strip()
        self.settings["discord_webhook_url"] = self.discord_url_input.text().strip()
        try:
            with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
                json.dump(self.settings, f, ensure_ascii=False, indent=2)
            self.webhook_status.append("✅ 設定已儲存")
        except Exception as e:
            self.webhook_status.append(f"❌ 儲存失敗: {e}")

    def send_line_test(self):
        user_id = self.get_last_user_id()
        if not user_id:
            QMessageBox.warning(self, "警告", "找不到綁定的 LINE 使用者 ID")
            self.webhook_status.append("❌ 發送失敗：找不到使用者 ID")
            return
        from linebot.v3.messaging import MessagingApi, Configuration, ApiClient
        from linebot.v3.messaging.models import TextMessage, PushMessageRequest
        access_token = self.line_token_input.text().strip()  # 


        try:
            config = Configuration(access_token=access_token)
            with ApiClient(config) as api_client:
                line_api = MessagingApi(api_client)
                msg = TextMessage(text="✅ 已發送 LINE 測試通知 (D-FLARE)")
                req = PushMessageRequest(to=user_id, messages=[msg])
                line_api.push_message(push_message_request=req)
            self.webhook_status.append("✅ 已發送 LINE 測試通知")
        except Exception as e:
            self.webhook_status.append(f"❌ LINE 發送失敗：{e}")
            QMessageBox.critical(self, "失敗", "LINE 發送失敗，請檢查權杖或網路")

    def send_discord_test(self):
        from D_FLARE_Notification import send_discord
        url = self.discord_url_input.text().strip()
        if not url:
            QMessageBox.warning(self, "Discord 測試", "請先輸入 Discord Webhook URL")
            return
        send_discord(url, "💬 D-FLARE 測試通知", callback=self.webhook_status.append)

    def trigger_notification(self, result_csv_path):
        """供外部 pipeline 呼叫自動推播"""
        from D_FLARE_Notification import notification_pipeline
        notification_pipeline(
            result_csv=result_csv_path,
            gemini_api_key=self.settings.get("gemini_api_key", ""),
            line_channel_access_token=self.settings.get("line_channel_access_token", ""),
            line_webhook_url=self.settings.get("line_webhook_url", ""),
            discord_webhook_url=self.settings.get("discord_webhook_url", ""),
            ui_callback=self.webhook_status.append
        )

    def get_last_user_id(self):
        if os.path.exists("last_user.txt"):
            with open("last_user.txt", "r") as f:
                uid = f.read().strip()
                if uid:
                    return uid
        if os.path.exists("line_users.txt"):
            with open("line_users.txt", "r") as f:
                ids = [line.strip() for line in f if line.strip()]
                if ids:
                    return ids[-1]
        return None

class VisualizerWidget(QWidget):
    def __init__(self, log_fetcher_widget=None):
        super().__init__()
        self.log_fetcher_widget = log_fetcher_widget

        layout = QVBoxLayout()
        title = QLabel("圖表產生模組")
        title.setStyleSheet("font-size: 15pt; font-weight: bold; font-family: 'PingFang TC', 'Open Sans';")
        layout.addWidget(title)

        # === 選擇資料夾 + 新增同步按鈕 ===
        self.folder_input = QLineEdit()
        self.folder_input.setPlaceholderText("請選擇模型預測輸出的圖表資料夾")
        self.select_folder_btn = QPushButton("選擇資料夾")
        self.select_folder_btn.clicked.connect(self.choose_folder)

        # ⬇️ 新增「同步清洗資料夾路徑」按鈕
        self.sync_btn = QPushButton("同步清洗資料夾路徑")
        self.sync_btn.clicked.connect(self.sync_folder_path)

        folder_layout = QHBoxLayout()
        folder_layout.addWidget(self.folder_input)
        folder_layout.addWidget(self.select_folder_btn)
        folder_layout.addWidget(self.sync_btn) 

        layout.addLayout(folder_layout)  # 加在四個圖表按鈕上面！


        # === 四個按鈕 ===
        btn_layout = QHBoxLayout()
        self.binary_bar_btn = QPushButton("二元長條圖")
        self.binary_pie_btn = QPushButton("二元圓餅圖")
        self.multi_bar_btn = QPushButton("多元長條圖")
        self.multi_pie_btn = QPushButton("多元圓餅圖")
        btn_layout.addWidget(self.binary_bar_btn)
        btn_layout.addWidget(self.binary_pie_btn)
        btn_layout.addWidget(self.multi_bar_btn)
        btn_layout.addWidget(self.multi_pie_btn)
        layout.addLayout(btn_layout)

        # === 圖片顯示區 ===
        self.image_label = QLabel("圖表預覽")
        self.image_label.setAlignment(Qt.AlignCenter)
        self.image_label.setStyleSheet("background-color: #fafafa; border: 1px solid #e0e0e0;")
        self.image_label.setFixedHeight(480)
        layout.addWidget(self.image_label)

        layout.addStretch()
        self.setLayout(layout)


        # 綁定事件
        self.binary_bar_btn.clicked.connect(lambda: self.display_image("binary_bar.png"))
        self.binary_pie_btn.clicked.connect(lambda: self.display_image("binary_pie.png"))
        self.multi_bar_btn.clicked.connect(lambda: self.display_image("multiclass_bar.png"))
        self.multi_pie_btn.clicked.connect(lambda: self.display_image("multiclass_pie.png"))

    def sync_folder_path(self):
        if self.log_fetcher_widget:
            path = self.log_fetcher_widget.clean_csv_dir_input.text()
            if path:
                self.folder_input.setText(path)


    def choose_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "選擇存放圖表的資料夾")
        if folder:
            self.folder_input.setText(folder)

    def display_image(self, filename):
        folder = self.folder_input.text().strip()
        if not folder:
            self.image_label.setText("⚠️ 請先選擇圖表資料夾")
            return
        path = os.path.join(folder, filename)
        if os.path.exists(path):
codex/allow-data-overlay-on-new-chart-1i37t9
            pixmap = QPixmap(path)
            pixmap = pixmap.scaled(
                self.image_label.width(),
                self.image_label.height(),
                Qt.KeepAspectRatio,
                Qt.SmoothTransformation,
            )
 codex/allow-data-overlay-on-new-chart-1i37t9
            self.image_label.setPixmap(pixmap)
            self.image_label.setText("")  # 清除預設文字
        else:
            self.image_label.setPixmap(QPixmap())
            self.image_label.setText(f"⚠️ 找不到圖表檔案：\n{filename}")

class DataCleanerWidget(QWidget):
    # ============ 外部協同：通知主流程暫停/恢復 Pipeline ============
    # 主程式須 connect 這兩個 signal 到 slot 處理主流程暫停/恢復
    request_pause = pyqtSignal()    # 通知主流程暫停
    request_resume = pyqtSignal()   # 通知主流程恢復

    def __init__(self):
        super().__init__()
        layout = QVBoxLayout()

        # 標題
        title = QLabel("資料清除模組")
        title.setStyleSheet("font-size: 15pt; font-weight: bold; font-family: 'PingFang TC', 'Open Sans';")
        layout.addWidget(title)

        # === 清除設定區 ===
        group = QGroupBox("清除設定")
        group_layout = QFormLayout()

        # 資料夾選擇
        self.folder_input = QLineEdit()
        self.folder_input.setPlaceholderText("請選擇要清理的資料夾")
        folder_btn = QPushButton("選擇")
        folder_btn.clicked.connect(self.choose_folder)
        folder_layout = QHBoxLayout()
        folder_layout.addWidget(self.folder_input)
        folder_layout.addWidget(folder_btn)
        group_layout.addRow("🗂️ 目標資料夾：", folder_layout)

        # 保留時數
        self.retention_input = QSpinBox()
        self.retention_input.setMinimum(1)
        self.retention_input.setValue(3)
        group_layout.addRow("⏰ 保留小時數：", self.retention_input)
        retention_tip = QLabel("只保留這段時間內的檔案（以最後修改時間為準），超過時數會自動刪除。")
        retention_tip.setStyleSheet("color: #666; font-size: 9pt; margin-bottom: 4px;")
        group_layout.addRow("", retention_tip)


        # 支援副檔名（可擴充）
        self.extensions = ['.csv', '.png', '.log']  # 可自行擴充

        # 自動清理間隔設定
        self.interval_input = QSpinBox()
        self.interval_input.setRange(1, 168)  # 1~168小時
        self.interval_input.setValue(6)
        group_layout.addRow("🔁 自動清理間隔（小時）：", self.interval_input)

        # 狀態顯示
        self.status_label = QLabel("⏸️ 尚未啟動自動清理")
        group_layout.addRow("📟 狀態：", self.status_label)
        # 加一行空行讓間距變多
        spacer = QLabel("")
        spacer.setFixedHeight(10)   # 你可以調整 10→15→20，看你喜歡多寬
        group_layout.addRow("", spacer)

        # --- 操作按鈕 ---
        btn_layout = QHBoxLayout()
        self.auto_btn = QPushButton("啟動自動清理")
        self.auto_btn.clicked.connect(self.toggle_auto_clean)
        btn_layout.addWidget(self.auto_btn)

        self.manual_btn = QPushButton("啟動手動清理")
        self.manual_btn.clicked.connect(self.manual_clean)
        btn_layout.addWidget(self.manual_btn)

        self.batch_btn = QPushButton("批次清空所有分析檔案")
        self.batch_btn.setStyleSheet("background-color: #e57373; color: white;")
        self.batch_btn.clicked.connect(self.batch_delete_files)
        btn_layout.addWidget(self.batch_btn)

        group_layout.addRow(btn_layout)
        group.setLayout(group_layout)
        layout.addWidget(group)

        # Log 區
        self.log_output = QTextEdit()
        self.log_output.setFixedHeight(200)
        layout.addWidget(self.log_output)
        layout.addStretch()
        self.setLayout(layout)

        # === 按鈕註解說明區 ===
        note = QLabel(
            "※啟動自動清理：每隔 N 小時會自動檢查並清除超過保留時數的舊檔案，讓你不用自己手動整理。\n"
            "※啟動手動清理：現在馬上依照上方設定，幫你清除超過保留小時數的舊檔案。\n"
            "※批次清空所有分析檔案：不論檔案多久以前產生，一次全部刪除，請謹慎操作！"
        )
        note.setStyleSheet("color: #888; font-size: 10pt; margin-top: 6px;")
        layout.addWidget(note)

        layout.addStretch()  # 保持靠上
        self.setLayout(layout)

        # --- Timer ---
        self.auto_timer = QTimer(self)
        self.auto_timer.timeout.connect(self._auto_clean_handler)
        self._auto_running = False      # 自動模式旗標
        self._cleaning = False          # 是否正在清理，防止重複觸發

    # =================== UI選擇 ===================
    def choose_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "選擇要清理的資料夾")
        if folder:
            self.folder_input.setText(folder)

    # =================== 自動定時清理 ===================
    def toggle_auto_clean(self):
        if self._auto_running:
            self.auto_timer.stop()
            self._auto_running = False
            self.status_label.setText("⏸️ 已停止自動清理")
            self.auto_btn.setText("啟動自動清理")
            self.log_output.append("[自動] 已手動停止自動清理。")
            # 如果有暫停主流程可恢復
            self.request_resume.emit()
            self.enable_buttons()
        else:
            interval = self.interval_input.value()
            self.auto_timer.start(interval * 3600 * 1000)  # 小時→毫秒
            self._auto_running = True
            self.status_label.setText(f"🟢 自動清理啟動，每 {interval} 小時執行")
            self.auto_btn.setText("停止自動清理")
            self.log_output.append(f"[自動] 自動清理已啟動，每 {interval} 小時執行。")
            self.disable_buttons()
            self.auto_btn.setEnabled(True)  # 保留可停止
            # 馬上做第一次
            QTimer.singleShot(100, self._auto_clean_handler)

    def _auto_clean_handler(self):
        # 防止重入（只允許一個清理流程）
        if self._cleaning:
            self.log_output.append("[自動] 清理進行中，略過此次排程。")
            return
        self._cleaning = True
        self.status_label.setText("⏳ 自動清理中…")
        self.disable_buttons()
        self.auto_btn.setEnabled(False)  # 清理時所有按鈕都 disable
        self.manual_btn.setEnabled(False)
        self.batch_btn.setEnabled(False)
        self.log_output.append(f"[自動] {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} 開始自動清理...")

        # 安全協同：通知主流程暫停
        self.request_pause.emit()
        # 真正清理
        self._do_clean_files(mode="auto")
        # 恢復主流程
        self.request_resume.emit()

        # 恢復按鈕狀態
        self.enable_buttons()
        self.auto_btn.setEnabled(True)
        self._cleaning = False
        self.status_label.setText("🟢 完成自動清理")
        self.log_output.append("[自動] 清理完成。\n")

    # =================== 手動立即清理 ===================
    def manual_clean(self):
        if self._cleaning:
            self.log_output.append("⚠️ 清理尚未結束，請稍候再執行。")
            return
        self._cleaning = True
        self.status_label.setText("⏳ 手動清理中…")
        self.disable_buttons()
        self.log_output.append(f"[手動] {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} 開始手動清理...")

        self.request_pause.emit()
        self._do_clean_files(mode="manual")
        self.request_resume.emit()

        self.enable_buttons()
        self._cleaning = False
        self.status_label.setText("🟢 完成手動清理")
        self.log_output.append("[手動] 清理完成。\n")

    # =================== 主要清理流程 ===================
    def _do_clean_files(self, mode="auto"):
        folder = self.folder_input.text().strip()
        keep_hours = self.retention_input.value()
        if not folder or not os.path.exists(folder):
            self.log_output.append("❗ 請先正確選擇資料夾！")
            return
        now = time.time()
        count, skipped, failed = 0, 0, 0
        removed, skip_files, fail_files = [], [], []

        # 可隨時擴充副檔名
        extensions = getattr(self, "extensions", ['.csv', '.png', '.log'])

        for file in os.listdir(folder):
            if any(file.lower().endswith(ext) for ext in extensions):
                fpath = os.path.join(folder, file)
                try:
                    mtime = os.path.getmtime(fpath)
                    hours = (now - mtime) / 3600
                    if hours > keep_hours:
                        try:
                            os.remove(fpath)
                            removed.append(file)
                            count += 1
                            self.log_output.append(
                                f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] 刪除 {file}（{hours:.1f} 小時前）")
                        except Exception as e:
                            failed += 1
                            fail_files.append(file)
                            self.log_output.append(f"❌ 無法刪除 {file}: {e}")
                    else:
                        skipped += 1
                        skip_files.append(file)
                except Exception as e:
                    failed += 1
                    fail_files.append(file)
                    self.log_output.append(f"❌ 讀取 {file} 發生例外: {e}")
        self.log_output.append(f"--- 本次清理結果 ---")
        self.log_output.append(f"刪除：{count} 筆；保留：{skipped} 筆；錯誤：{failed} 筆。")
        if count:
            self.log_output.append(f"已刪除：{removed}")
        if skip_files:
            self.log_output.append(f"保留未刪除：{skip_files}")
        if fail_files:
            self.log_output.append(f"發生錯誤：{fail_files}")

    # =================== 批次全部清空 ===================
    def batch_delete_files(self):
        if self._cleaning:
            self.log_output.append("⚠️ 清理尚未結束，請稍候再執行。")
            return
        self._cleaning = True
        self.status_label.setText("⏳ 批次清空中…")
        self.disable_buttons()
        self.log_output.append(f"[批次] {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} 開始批次清空...")

        self.request_pause.emit()
        folder = self.folder_input.text().strip()
        if not folder or not os.path.exists(folder):
            self.log_output.append("❗ 請先正確選擇資料夾！")
        else:
            extensions = getattr(self, "extensions", ['.csv', '.png', '.log'])
            count, failed = 0, 0
            removed, fail_files = [], []
            for file in os.listdir(folder):
                if any(file.lower().endswith(ext) for ext in extensions):
                    fpath = os.path.join(folder, file)
                    try:
                        os.remove(fpath)
                        removed.append(file)
                        count += 1
                        self.log_output.append(
                            f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] 批次刪除 {file}")
                    except Exception as e:
                        failed += 1
                        fail_files.append(file)
                        self.log_output.append(f"❌ 無法刪除 {file}: {e}")
            self.log_output.append(f"批次刪除完成，成功 {count} 筆，錯誤 {failed} 筆。")
            if count:
                self.log_output.append(f"已刪除：{removed}")
            if fail_files:
                self.log_output.append(f"發生錯誤：{fail_files}")
        self.request_resume.emit()
        self.enable_buttons()
        self._cleaning = False
        self.status_label.setText("🟢 批次清空完成")
        self.log_output.append("[批次] 清空完成。\n")

    # =================== UI 防呆輔助 ===================
    def disable_buttons(self):
        self.manual_btn.setEnabled(False)
        self.batch_btn.setEnabled(False)
        self.auto_btn.setEnabled(False)

    def enable_buttons(self):
        self.manual_btn.setEnabled(True)
        self.batch_btn.setEnabled(True)
        if not self._auto_running:
            self.auto_btn.setEnabled(True)
        else:
            self.auto_btn.setEnabled(True)  # 仍保留可手動停止

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("D-FLARE 控制中心")
        self.setMinimumSize(1000, 600)
        self.setWindowIcon(QIcon("icon.png"))

        
        self.notifier_widget = NotifierWidget()
        self.log_fetcher = LogFetcherWidget(notifier_widget=self.notifier_widget)
        self.visualizer = VisualizerWidget(log_fetcher_widget=self.log_fetcher)

        # 在 MainWindow.__init__ 裡加
        self.data_cleaner_widget = DataCleanerWidget()
        self.data_cleaner_widget.request_pause.connect(self.pause_pipeline)    # 讓主流程暫停
        self.data_cleaner_widget.request_resume.connect(self.resume_pipeline)  # 讓主流程恢復

        main_widget = QWidget()
        main_layout = QHBoxLayout()

        self.list_widget = QListWidget()
        self.list_widget.setFixedWidth(200)
        app.setStyleSheet("""
        QWidget {
            font-family: 'PingFang TC', 'Open Sans', sans-serif;
            font-size: 15px;
            background-color: #f8f8f8;
            color: #2c2c2c;
        }

        QListWidget {
            border: none;
            background-color: #ffffff;
        }

        QListWidget::item {
            padding: 10px;
            border-bottom: 1px solid #dcdcdc;
        }

        QListWidget::item:selected {
            background-color: #007aff;
            color: white;
            border-radius: 8px;
        }

        QPushButton {
            background-color: #f0f0f0;
            border: 1px solid #cfcfcf;
            border-radius: 6px;
            padding: 5px 10px;
        }

        QPushButton:hover {
            background-color: #e0e0e0;
        }

        QLineEdit, QComboBox, QTextEdit {
            background-color: #ffffff;
            border: 1px solid #cccccc;
            border-radius: 6px;
            padding: 4px;
        }

        QGroupBox {
            border: 1px solid #e0e0e0;
            border-radius: 8px;
            margin-top: 10px;
        }

        QGroupBox::title {
            subcontrol-origin: margin;
            subcontrol-position: top left;
            padding: 0 5px;
            font-weight: bold;
        }

        QLabel {
            padding: 2px;
        }
    """)


        modules = [
            "🔔 通知推播",
            "📄 Log 擷取",
            "📊 圖表產生",
            "🗑 資料清除",
        ]
        for module in modules:
            self.list_widget.addItem(QListWidgetItem(module))

        self.stack = QStackedWidget()
        self.stack.addWidget(NotifierWidget())  # 🔔 通知推播頁
        self.stack.addWidget(self.log_fetcher) 
        self.stack.addWidget(self.visualizer)
        self.stack.addWidget(DataCleanerWidget()) # 🗑 資料清除頁

        self.list_widget.currentRowChanged.connect(self.stack.setCurrentIndex)
        self.list_widget.setStyleSheet("""
        QListWidget {
            border: none;
            outline: none;
            background-color: #ffffff;
        }

        QListWidget::item {
            padding: 6px 12px;
            margin: 2px;
            border-radius: 6px;
        }

        QListWidget::item:selected {
            background-color: #e6f0ff;  /* 淺藍底 */
            border: 2px solid #0078d7;  /* 深藍外框 */
            color: black;
        }

        QListWidget::item:focus {
            outline: none;
        }

        QListWidget::item:selected:focus {
            outline: none;
        }
                                        
        QListWidget::item:hover {
        background-color: #f2faff;
    }
                                    
    """)


        main_layout.addWidget(self.list_widget)
        main_layout.addWidget(self.stack)
        main_widget.setLayout(main_layout)
        self.setStyleSheet("""
        QLabel, QLineEdit, QPushButton, QComboBox, QCheckBox, QTextEdit, QSpinBox {
            font-size: 11pt;
        }

        QListWidget::item:focus {
            outline: none;  /* 移除虛線 */
        }

        QListWidget::item:selected:focus {
            outline: none;  /* 選取 + 聚焦時也不要虛線 */
        }
                            
        QListWidget::item:selected {
        background-color: #0078d7;
        color: white;
        border-radius: 5px;
        margin: 2px;
    }
                        
    """)

        self.setCentralWidget(main_widget)
        self.init_tray()

    def init_tray(self):
        tray = QSystemTrayIcon(self)
        tray.setIcon(QIcon("icon.png"))
        tray.setVisible(True)
        menu = QMenu()
        menu.addAction(QAction("開啟 UI", self, triggered=self.showNormal))
        menu.addAction(QAction("全部啟動", self, triggered=lambda: print("🚀 所有模組啟動")))
        menu.addSeparator()
        menu.addAction(QAction("關閉程式", self, triggered=QApplication.quit))
        tray.setContextMenu(menu)

    def closeEvent(self, event):
        reply = QMessageBox.question(self, "關閉確認", "確定要結束程式嗎？",
                                     QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if reply == QMessageBox.Yes:
            event.accept()
        else:
            event.ignore()

    # ====== slot: 暫停主流程（清理前呼叫）======
    def pause_pipeline(self):
        # 例：暫停 log 監聽的 timer 或 pipeline 處理
        try:
            self.log_fetcher_widget.poll_timer.stop()
            self.log_fetcher_widget.auto_clean_timer.stop()
            print("主流程暫停：log 輪詢與自動清洗已停止。")
        except Exception as e:
            print(f"暫停主流程例外: {e}")

    # ====== slot: 恢復主流程（清理完呼叫）======
    def resume_pipeline(self):
        # 例：恢復 log 監聽 timer
        try:
            self.log_fetcher_widget.poll_timer.start(5000)  # 5 秒
            print("主流程恢復：log 輪詢已恢復。")
        except Exception as e:
            print(f"恢復主流程例外: {e}")

if __name__ == "__main__":
    app = QApplication(sys.argv)

    # 加入 macOS 蘋果風格
    app.setStyleSheet("""
    QWidget {
        font-family: 'PingFang TC', 'Open Sans', sans-serif;
        font-size: 15px;
        background-color: #f8f8f8;
        color: #2c2c2c;
    }

    QListWidget {
        border: none;
        background-color: #ffffff;
    }

    QListWidget::item {
        padding: 11px;
        border-bottom: 1px solid #dcdcdc;
    }

    QListWidget::item:selected {
        background-color: #007aff;
        color: white;
        border-radius: 10px;
    }

    QPushButton {
        background-color: #f0f0f0;
        border: 1px solid #cfcfcf;
        border-radius: 6px;
        padding: 5px 10px;
    }

    QPushButton:hover {
        background-color: #e0e0e0;
    }

    QLineEdit, QComboBox, QTextEdit {
        background-color: #ffffff;
        border: 1px solid #cccccc;
        border-radius: 6px;
        padding: 4px;
    }

    QGroupBox {
        border: 1px solid #e0e0e0;
        border-radius: 8px;
        margin-top: 10px;
    }

    QGroupBox::title {
        subcontrol-origin: margin;
        subcontrol-position: top left;
        padding: 0 5px;
        font-weight: bold;
    }

    QLabel {
        padding: 2px;
    }
""")

    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
