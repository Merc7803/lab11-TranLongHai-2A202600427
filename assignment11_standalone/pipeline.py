import time
from typing import Dict
import layers
import models

class DefensePipeline:
    """Orchestrates all safety layers in order."""

    def __init__(self):
        self.rate_limiter = layers.RateLimiter(max_requests=10, window_seconds=60)
        self.session_det = layers.SessionAnomalyDetector(max_suspicious=3)
        self.input_guard = layers.InputGuardrails()
        self.output_guard = layers.OutputGuardrails()
        self.agent = models.BankingAgent()
        self.judge = models.LLMJudge(min_score=3)
        self.audit = layers.AuditLog()

    def process(self, user_input: str, user_id: str = "user_001") -> Dict:
        start_time = time.time()
        
        entry = {
            "user_id": user_id,
            "input": user_input,
            "blocked": False,
            "blocked_by": None,
            "block_reason": None,
            "response": None,
            "judge_scores": None,
            "redacted": [],
            "latency_ms": 0,
        }

        def _block(layer: str, reason: str, msg: str):
            entry.update(blocked=True, blocked_by=layer, block_reason=reason, response=msg)
            entry["latency_ms"] = int((time.time() - start_time) * 1000)
            self.audit.record(entry)
            return entry

        try:
            # 1. Rate Limiter
            ok, msg = self.rate_limiter.check(user_id)
            if not ok: return _block("RateLimiter", "limit_exceeded", msg)

            # 2. Session Anomaly
            ok, msg = self.session_det.check(user_id, user_input)
            if not ok: return _block("SessionAnomaly", "suspicious_behavior", msg)

            # 3. Input Guardrails
            ok, reason, pattern = self.input_guard.check(user_input)
            if not ok: return _block("InputGuardrails", pattern, reason)

            # 4. LLM Call
            raw_response = self.agent.call(user_input)

            # 5. Output Guardrails
            clean_response, redacted = self.output_guard.filter(raw_response)
            entry["redacted"] = redacted

            # 6. LLM Judge
            verdict = self.judge.evaluate(clean_response)
            entry["judge_scores"] = verdict["scores"]

            if verdict["verdict"] == "FAIL":
                return _block("LLMJudge", f"fail:{verdict['reason']}", 
                              "I'm unable to provide that response. Please rephrase.")

            # Success
            entry["response"] = clean_response
            entry["latency_ms"] = int((time.time() - start_time) * 1000)
            self.audit.record(entry)
            return entry

        except Exception as e:
            return _block("PipelineError", str(e), "An internal error occurred.")
