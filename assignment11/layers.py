import re
import time
import json
from datetime import datetime
from collections import defaultdict, deque
from typing import Optional, Dict, List, Tuple

# ============================================================
# LAYER 1: RATE LIMITER
# ============================================================
class RateLimiter:
    def __init__(self, max_requests: int = 10, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.user_windows: Dict[str, deque] = defaultdict(deque)
        self.hit_count = 0

    def check(self, user_id: str) -> Tuple[bool, Optional[str]]:
        now = time.time()
        window = self.user_windows[user_id]
        while window and window[0] < now - self.window_seconds:
            window.popleft()

        if len(window) >= self.max_requests:
            wait = int(self.window_seconds - (now - window[0])) + 1
            self.hit_count += 1
            return False, f"Rate limit exceeded. Please wait {wait} seconds."

        window.append(now)
        return True, None

# ============================================================
# LAYER 2: SESSION ANOMALY DETECTOR (BONUS)
# ============================================================
class SessionAnomalyDetector:
    SUSPICION_SIGNALS = [
        r"ignore|override|bypass|jailbreak",
        r"system\s*prompt|reveal|expose|show\s+me\s+(your|the)",
        r"password|secret|credential|api[\s_]key|token",
        r"pretend|roleplay|act\s+as|you\s+are\s+now",
        r"[<>{}\\]",
        r"base64|hex\s+encode|rot13",
    ]

    def __init__(self, max_suspicious: int = 3, window_messages: int = 10):
        self.max_suspicious = max_suspicious
        self.window_messages = window_messages
        self.history: Dict[str, deque] = defaultdict(deque)
        self.block_count = 0

    def check(self, user_id: str, text: str) -> Tuple[bool, Optional[str]]:
        h = self.history[user_id]
        lower = (text or "").lower()
        is_suspicious = any(re.search(p, lower, re.IGNORECASE) for p in self.SUSPICION_SIGNALS)
        h.append({"suspicious": is_suspicious, "ts": time.time()})
        while len(h) > self.window_messages:
            h.popleft()

        n_suspicious = sum(1 for x in h if x["suspicious"])
        if n_suspicious >= self.max_suspicious:
            self.block_count += 1
            return False, f"BLOCK: Session flagged: {n_suspicious} suspicious messages detected."
        return True, None

# ============================================================
# LAYER 3: INPUT GUARDRAILS
# ============================================================
class InputGuardrails:
    INJECTION_PATTERNS = [
        (r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions?", "ignore_instructions"),
        (r"you\s+are\s+now\s+(DAN|jailbreak|unrestricted|evil|root|admin|god)", "persona_override"),
        (r"(reveal|show|print|output|dump|expose|leak)\s+(the\s+)?(system\s+prompt|api[\s_]key|password|credential|secret|config)", "credential_extraction"),
        (r"translate\s+(your\s+)?(system\s+prompt|instructions?)\s+to", "prompt_extraction"),
        (r"per\s+ticket\s+\w+-\d+", "fake_authority"),
        (r"fill\s+in\s*:\s*(the\s+)?(password|key|secret|credential|connection)", "fill_in_attack"),
        (r"(write\s+a\s+story|roleplay|pretend|imagine|hypothetically|act\s+as).{0,80}(password|secret|credential|api.?key)", "indirect_extraction"),
    ]
    
    BANKING_KEYWORDS = [
        r"account|balance|transfer|payment|card|credit|debit",
        r"loan|mortgage|interest|savings|deposit|withdraw",
        r"atm|branch|fee|transaction|statement|pin|verify",
        r"tài\s+khoản|chuyển\s+khoản|thẻ|lãi\s+suất|tiết\s+kiệm",
    ]

    def __init__(self):
        self.block_count = 0

    def check(self, text: str) -> Tuple[bool, Optional[str], Optional[str]]:
        stripped = (text or "").strip()
        if not stripped: return False, "Empty input not allowed.", "empty"
        if len(stripped) > 5000: return False, "Input too long.", "too_long"

        lower = stripped.lower()
        for pattern, label in self.INJECTION_PATTERNS:
            if re.search(pattern, lower, re.IGNORECASE | re.DOTALL):
                self.block_count += 1
                return False, "BLOCK: Request blocked: potential prompt injection.", label

        is_banking = any(re.search(kw, lower, re.IGNORECASE) for kw in self.BANKING_KEYWORDS)
        if not is_banking and len(stripped.split()) > 5:
            self.block_count += 1
            return False, "I can only assist with banking topics.", "off_topic"
            
        return True, None, None 

# ============================================================
# LAYER 4: OUTPUT GUARDRAILS
# ============================================================
class OutputGuardrails:
    PII_PATTERNS = [
        (r"\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b", "[CARD_REDACTED]", "card"),
        (r"\b\d{9,14}\b", "[ACCOUNT_REDACTED]", "account"),
        (r"\b0\d{9}\b", "[PHONE_REDACTED]", "phone"),
        (r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b", "[EMAIL_REDACTED]", "email"),
        (r"sk-[A-Za-z0-9]{20,}", "[API_KEY_REDACTED]", "api_key"),
    ]

    def __init__(self):
        self.redaction_count = 0

    def filter(self, response: str) -> Tuple[str, List[str]]:
        redacted_types = []
        filtered = response
        for pattern, replacement, label in self.PII_PATTERNS:
            new = re.sub(pattern, replacement, filtered, flags=re.IGNORECASE)
            if new != filtered:
                redacted_types.append(label)
                filtered = new
                self.redaction_count += 1
        return filtered, redacted_types

# ============================================================
# LAYER 5: AUDIT & MONITORING
# ============================================================
class AuditLog:
    def __init__(self, log_path: str = "audit_log.json"):
        self.entries = []
        self.log_path = log_path

    def record(self, entry: dict):
        entry["timestamp"] = datetime.utcnow().isoformat() + "Z"
        self.entries.append(entry)

    def export(self):
        with open(self.log_path, "w", encoding="utf-8") as f:
            json.dump(self.entries, f, indent=2, ensure_ascii=False)

class Monitoring:
    def __init__(self, layers_dict: dict):
        self.layers = layers_dict

    def report(self):
        print("\n" + "="*50)
        print("MONITORING REPORT")
        print("="*50)
        for name, layer in self.layers.items():
            if hasattr(layer, 'block_count'):
                print(f"  {name:<25}: {layer.block_count} blocks")
            elif hasattr(layer, 'hit_count'):
                print(f"  {name:<25}: {layer.hit_count} hits")
            elif hasattr(layer, 'redaction_count'):
                print(f"  {name:<25}: {layer.redaction_count} redactions")
        print("="*50)
