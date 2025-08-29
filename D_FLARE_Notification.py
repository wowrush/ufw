import os
import requests
import json

USER_FILE = "line_users.txt"

def load_line_users(user_file=USER_FILE):
    if not os.path.exists(user_file):
        return []
    with open(user_file, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]

def push_line_message(access_token, user_id, msg):
    url = "https://api.line.me/v2/bot/message/push"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }
    payload = {
        "to": user_id,
        "messages": [{"type": "text", "text": msg}]
    }
    res = requests.post(url, headers=headers, json=payload)
    return res.status_code == 200

def send_line_to_all(access_token, msg, callback=None):
    user_ids = load_line_users()
    if not access_token or len(access_token) < 10:
        if callback: callback("❌ 請正確設定 LINE Channel Access Token")
        return False
    if not user_ids:
        if callback: callback("❌ 尚無任何 LINE 使用者，請先掃碼加 Bot 並傳訊息！")
        return False
    ok, fail = 0, 0
    for uid in user_ids:
        if push_line_message(access_token, uid, msg):
            ok += 1
            if callback: callback(f"✅ 已發送給 {uid}")
        else:
            fail += 1
            if callback: callback(f"❌ 傳送失敗 {uid}")
    return ok > 0

def send_discord(webhook_url, msg, callback=None):
    if not webhook_url: return False
    try:
        resp = requests.post(webhook_url, json={"content": msg})
        if resp.status_code in [200, 204]:
            if callback: callback("✅ Discord 已發送")
            return True
        else:
            if callback: callback(f"❌ Discord 發送失敗，狀態碼：{resp.status_code}")
            return False
    except Exception as e:
        if callback: callback(f"❌ Discord 發送例外：{e}")
        return False

def ask_gemini(log_desc, gemini_api_key):
    try:
        from google.generativeai import configure, GenerativeModel
        configure(api_key=gemini_api_key)
        gemini = GenerativeModel('models/gemini-1.5-flash')
        prompt = (
            "你是一位資安分析師。請用繁體中文簡短回覆以下兩段建議，每段不限制兩句，取消任何格式標記：\n"
            "1. 威脅說明：這筆日誌描述了什麼潛在風險？\n"
            "2. 防禦建議：該如何立即應對與預防？\n"
            f"事件日誌：{log_desc}"
        )
        resp = gemini.generate_content(prompt)
        return resp.text.strip()
    except Exception as e:
        return f"（無法取得 AI 建議：{e}）"

def notification_pipeline(
    result_csv,
    gemini_api_key,
    line_channel_access_token,
    line_webhook_url,
    discord_webhook_url,
    ui_callback
):
    import pandas as pd
    if not os.path.exists(result_csv):
        if ui_callback: ui_callback(f"❌ 結果檔不存在：{result_csv}")
        return
    try:
        df = pd.read_csv(result_csv)
    except Exception as e:
        if ui_callback: ui_callback(f"❌ 讀取結果 CSV 失敗：{e}")
        return

    # 預設高風險分級
    high_sev = df[df['Severity'].astype(str).isin(['1','2','3'])]
    if high_sev.empty:
        if ui_callback: ui_callback("（本批次無高風險事件，不推播）")
        return

    for _, row in high_sev.iterrows():
        src_ip = str(row.get('SourceIP', ''))
        sev = str(row.get('Severity', ''))
        desc = str(row.get('Description', ''))
        gemini_suggestion = ""
        if gemini_api_key:
            gemini_suggestion = ask_gemini(desc, gemini_api_key)
        msg = (
            "🚨 偵測到高風險事件\n"
            f"等級：{sev}\n"
            f"來源 IP：{src_ip}\n"
            f"描述：{desc}\n"
            f"{gemini_suggestion}"
        )

        send_line_to_all(line_channel_access_token, msg, callback=ui_callback)
        send_discord(discord_webhook_url, msg, callback=ui_callback)
    if ui_callback: ui_callback("🎉 本批次高風險事件已全數推播")

# --- Flask Webhook server（建議獨立運作，僅範例呈現，可直接從 line_webhook_server.py 搬過來用）---
def run_line_webhook_server(channel_secret, access_token, host="0.0.0.0", port=8000):
    from flask import Flask, request, abort
    from linebot.v3.webhook import WebhookHandler
    from linebot.v3.webhooks import MessageEvent, TextMessageContent
    from linebot.v3.messaging import Configuration, ApiClient, MessagingApi

    app = Flask(__name__)
    handler = WebhookHandler(channel_secret)

    @app.route("/callback", methods=["POST"])
    def callback():
        signature = request.headers["X-Line-Signature"]
        body = request.get_data(as_text=True)
        try:
            handler.handle(body, signature)
        except Exception as e:
            print("Webhook 處理失敗", e)
            abort(400)
        return "OK"

    @handler.add(MessageEvent, message=TextMessageContent)
    def handle_message(event):
        user_id = event.source.user_id
        # 註冊/更新 user_id
        if user_id:
            ids = set(load_line_users())
            ids.add(user_id)
            with open(USER_FILE, "w", encoding="utf-8") as f:
                for uid in ids:
                    f.write(uid + "\n")
            with open("last_user.txt", "w", encoding="utf-8") as f:
                f.write(user_id)
        # 回覆歡迎
        try:
            config = Configuration(access_token=access_token)
            with ApiClient(config) as api_client:
                line_api = MessagingApi(api_client)
                line_api.push_message(user_id, [
                    {"type": "text", "text": "✅ 已註冊，成功加入 D-FLARE 威脅通知"}
                ])
        except Exception as e:
            print("回覆歡迎訊息失敗：", e)

    print(f"LINE Webhook 伺服器啟動於 http://{host}:{port}/callback")
    app.run(host=host, port=port)

# --- main 測試用 ---
if __name__ == "__main__":
    # 若要測試 webhook server，請啟動這行（參數自行設置）
    # run_line_webhook_server(channel_secret="你的secret", access_token="你的token")
    # 或直接推播測試
    notification_pipeline(
        result_csv="your_result.csv",
        line_channel_access_token="你的token",
        discord_webhook_url="",
        gemini_api_key=""
    )
