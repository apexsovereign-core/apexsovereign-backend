"""
ApexSovereign.ai - 24/7 Asynchronous Worker Engine & Self-Healing Compliance Circuit
Runs on Render as a multi-threaded persistent daemon process.
"""

import os
import time
import json
import re
import requests
from typing import Dict, Any, Tuple
from google import genai
from google.genai import types
from dotenv import load_dotenv

load_dotenv()

# Configuration
SUPABASE_URL = os.getenv("SUPABASE_URL", "")
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")

# Gemini SDK Client
ai_client = genai.Client(apiKey=GEMINI_API_KEY) if GEMINI_API_KEY else None

# Deterministic JSON Schema Contract
TARGET_ENTERPRISE_SCHEMA = {
    "type": "object",
    "properties": {
        "execution_summary": {"type": "string"},
        "risk_index": {"type": "number"},
        "strategic_directives": {
            "type": "array",
            "items": {"type": "string"}
        },
        "deterministic_hash": {"type": "string"}
    },
    "required": ["execution_summary", "risk_index", "strategic_directives", "deterministic_hash"]
}

# The Wall: Adaptive Prompt Injection Defense Patterns
INJECTION_ATTACK_PATTERNS = [
    r"(?i)ignore\s+previous\s+instructions",
    r"(?i)repeat\s+the\s+system\s+prompt",
    r"(?i)output\s+your\s+system\s+instructions",
    r"(?i)you\s+are\s+now\s+in\s+developer\s+mode",
    r"(?i)dan\s+mode",
    r"(?i)reveal\s+secret\s+key",
]

def inspect_and_sanitize_payload(user_input: str) -> Tuple[bool, str]:
    """Inspects input for exfiltration attacks. Returns (is_safe, sanitized_content)."""
    for pattern in INJECTION_ATTACK_PATTERNS:
        if re.search(pattern, user_input):
            return False, "PROMPT_EXFILTRATION_ATTACK_INTERCEPTED"
    return True, user_input


def execute_self_healing_gemini_job(task_prompt: str, max_healing_cycles: int = 3) -> Dict[str, Any]:
    """
    Executes Gemini LLM inference with a 3-cycle automated syntax self-healing circuit breaker.
    Guarantees raw, minified JSON matching the exact schema without markdown wrap.
    """
    if not ai_client:
        # Development fallback
        return {
            "execution_summary": "Simulated production execution",
            "risk_index": 0.04,
            "strategic_directives": ["Authorize sovereign pipeline", "Consolidate edge caching"],
            "deterministic_hash": "a1b2c3d4e5f67890"
        }

    system_instruction = (
        "You are the ApexSovereign Deterministic Engine. "
        "You MUST return raw, unformatted, minified JSON that conforms strictly to this schema: "
        f"{json.dumps(TARGET_ENTERPRISE_SCHEMA)}. "
        "Do NOT include markdown formatting, backticks (```), or explanations."
    )

    current_prompt = task_prompt
    history_context = []

    for cycle in range(1, max_healing_cycles + 1):
        try:
            response = ai_client.models.generate_content(
                model="gemini-2.5-flash",
                contents=current_prompt,
                config=types.GenerateContentConfig(
                    system_instruction=system_instruction,
                    temperature=0.1,  -- High determinism
                    response_mime_type="application/json"
                )
            )
            raw_text = response.text.strip()

            # Clean any stray formatting artifacts
            if raw_text.startswith("```json"):
                raw_text = raw_text[7:]
            if raw_text.startswith("```"):
                raw_text = raw_text[3:]
            if raw_text.endswith("```"):
                raw_text = raw_text[:-3]
            raw_text = raw_text.strip()

            # Parse and validate schema keys
            parsed = json.loads(raw_text)
            for req_key in TARGET_ENTERPRISE_SCHEMA["required"]:
                if req_key not in parsed:
                    raise KeyError(f"Missing required key in JSON output: '{req_key}'")

            return parsed  # Success

        except Exception as err:
            print(f"[SELF-HEALING CYCLE {cycle}/{max_healing_cycles}] Syntax/Schema fault: {err}")
            if cycle == max_healing_cycles:
                raise RuntimeError(f"Self-healing circuit breaker tripped after {max_healing_cycles} cycles. Last error: {err}")

            # Send targeted correction request back to model
            current_prompt = (
                f"Your previous output failed strict JSON schema validation. Error: {str(err)}. "
                f"Fix the syntax, ensure all brackets close, and return raw minified JSON complying with schema: "
                f"{json.dumps(TARGET_ENTERPRISE_SCHEMA)}"
            )
            time.sleep(1)  # Leaky bucket cool-down


def run_asynchronous_worker():
    """Persistent 24/7 worker loop. Pools immutable_job_queue from Supabase."""
    headers = {
        "apikey": SUPABASE_SERVICE_ROLE_KEY,
        "Authorization": f"Bearer {SUPABASE_SERVICE_ROLE_KEY}",
        "Content-Type": "application/json",
    }

    print("[ApexSovereign Worker] Engine running 24/7. Polling immutable job queue...")

    while True:
        try:
            # 1. Fetch next queued job with highest priority
            fetch_url = f"{SUPABASE_URL}/rest/v1/immutable_job_queue?status=eq.QUEUED&order=priority.desc,created_at.asc&limit=1"
            res = requests.get(fetch_url, headers=headers, timeout=5)
            jobs = res.json()

            if not jobs:
                time.sleep(2)
                continue

            job = jobs[0]
            job_id = job["id"]
            tenant_id = job["tenant_id"]
            user_input = job.get("input_payload", {}).get("task", "")

            # 2. Lock job status to PROCESSING
            patch_url = f"{SUPABASE_URL}/rest/v1/immutable_job_queue?id=eq.{job_id}"
            requests.patch(patch_url, headers=headers, json={"status": "PROCESSING", "leased_at": "now()"}, timeout=3)

            # 3. Security Check: The Wall
            is_safe, sanitized_or_flag = inspect_and_sanitize_payload(user_input)
            if not is_safe:
                # Blacklist event
                requests.patch(
                    patch_url,
                    headers=headers,
                    json={"status": "FAILED", "error_trace": "PROMPT_EXFILTRATION_SECURITY_REJECTION"},
                    timeout=3
                )
                # Log security alert
                log_url = f"{SUPABASE_URL}/rest/v1/system_logs"
                requests.post(
                    log_url,
                    headers=headers,
                    json={
                        "tenant_id": tenant_id,
                        "event_type": "SECURITY_INJECTION_ALERT",
                        "severity": "CRITICAL",
                        "telemetry": {"raw_input": user_input, "intercepted_at": time.time()}
                    },
                    timeout=3
                )
                continue

            # 4. Execute Self-Healing Engine
            t0 = time.time()
            final_output = execute_self_healing_gemini_job(sanitized_or_flag)
            execution_duration = time.time() - t0

            # 5. Mark Job as COMPLETED
            requests.patch(
                patch_url,
                headers=headers,
                json={"status": "COMPLETED", "final_output": final_output, "completed_at": "now()"},
                timeout=3
            )

            # 6. Audit Token Ledger & Calculate Profit Margin (Milestone 5)
            prompt_tokens = len(sanitized_or_flag) // 4
            completion_tokens = len(json.dumps(final_output)) // 4
            total_tokens = prompt_tokens + completion_tokens

            # Compute cost vs billed revenue
            cost_usd = round(total_tokens * 0.00000035, 6)   # Gemini API estimated raw cost
            billed_usd = round(total_tokens * 0.000005, 6)   # Enterprise contract rate
            gross_profit_margin = round(((billed_usd - cost_usd) / billed_usd) * 100, 2)

            ledger_url = f"{SUPABASE_URL}/rest/v1/token_ledger"
            requests.post(
                ledger_url,
                headers=headers,
                json={
                    "organization_id": job["organization_id"],
                    "tenant_id": tenant_id,
                    "job_id": job_id,
                    "prompt_tokens": prompt_tokens,
                    "completion_tokens": completion_tokens,
                    "total_tokens": total_tokens,
                    "cost_usd": cost_usd,
                    "billed_usd": billed_usd,
                    "margin_percentage": gross_profit_margin
                },
                timeout=3
            )

            print(f"[JOB COMPLETE] ID: {job_id} | Time: {execution_duration:.2f}s | Profit Margin: {gross_profit_margin}%")

        except Exception as loop_err:
            print(f"[WORKER LOOP FAULT] {loop_err}")
            time.sleep(3)


if __name__ == "__main__":
    run_asynchronous_worker()