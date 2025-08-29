from flask import Flask, request, abort
from linebot.v3.webhook import WebhookHandler
from linebot.v3.webhooks import MessageEvent, TextMessageContent
from linebot.v3.messaging import MessagingApi, Configuration, ApiClient
import os

# === LINE Bot 設定 ===
CHANNEL_ACCESS_TOKEN = "tOth3tgqUIYkjLxqBf44UsvXuTQQYBB571U7DdEHxCeaiAPIkfoKKgt2yl1GMq41d8QB5AGfCfONNck0/1gZaYHu6rjP94o7/vDepegafFcw61o8CK/8sH8MPsZcPK4nhlEBJKPY/Ml76/rbB0GB7wdB04t89/1O/w1cDnyilFU="
CHANNEL_SECRET = '4bdc8c433fd1c4b1ded803ed63103852'
USER_FILE = 'line_users.txt'

app = Flask(__name__)
handler = WebhookHandler(CHANNEL_SECRET)

# 確保 line_users.txt 存在
if not os.path.exists(USER_FILE):
    with open(USER_FILE, 'w'): pass

@app.route("/callback", methods=['POST'])
def callback():
    signature = request.headers.get('X-Line-Signature', '')
    body = request.get_data(as_text=True)
    try:
        handler.handle(body, signature)
    except Exception as e:
        print(f"❌ webhook 錯誤：{str(e)}")
        abort(400)
    return 'OK',200

@handler.add(MessageEvent)
def handle_message(event):
    user_id = event.source.user_id
    print(f"✅ 收到使用者 ID：{user_id}")
    
    # 記錄進 line_users.txt（維持不變）
    with open(USER_FILE, 'r+') as f:
        ids = set(line.strip() for line in f)
        if user_id not in ids:
            f.write(user_id + '\n')
            print("✅ 已寫入新使用者 ID")
    
    # 🆕 寫入最後一個使用者到 last_user.txt
    with open("last_user.txt", "w") as f_last:
        f_last.write(user_id)
        print("📝 已更新 last_user.txt 為最新使用者")


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
