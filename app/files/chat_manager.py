"""
Chat Manager — saves chat conversations to disk.
Path: data/history/chat/
"""
import os, json, time

CHAT_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
    "data", "history", "chat"
)

def save_chat(messages: list, session_id: str = "") -> str:
    os.makedirs(CHAT_DIR, exist_ok=True)
    ts    = time.strftime("%Y%m%d_%H%M%S")
    fname = f"chat_{ts}_{session_id or 'nosession'}.json"
    path  = os.path.join(CHAT_DIR, fname)
    payload = {
        "saved_at":  time.strftime("%Y-%m-%d %H:%M:%S"),
        "session_id": session_id,
        "message_count": len(messages),
        "messages": messages
    }
    with open(path, "w") as f:
        json.dump(payload, f, indent=2)
    return fname

def list_chats() -> list:
    if not os.path.isdir(CHAT_DIR):
        return []
    files = sorted(os.listdir(CHAT_DIR), reverse=True)
    return [f for f in files if f.endswith(".json")]
