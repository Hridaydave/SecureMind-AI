from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from datetime import datetime
import re
import uvicorn

app = FastAPI(
    title="SecureMind AI",
    description="AI Prompt Injection Detection & Security API",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Models ──────────────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    prompt: str
    user_id: str = "anonymous"

class ScanResult(BaseModel):
    score: int
    severity: str
    attack_type: str
    flags: list[str]
    verdict: str
    explanation: str
    timestamp: str

# ── Detection Engine ────────────────────────────────────────────────────────

THREAT_PATTERNS = [
    {
        "pattern": r"ignore (all |previous |your |above |any )?(instructions?|prompts?|rules?|context)",
        "score": 40,
        "label": "Instruction override detected",
        "type": "Prompt Injection"
    },
    {
        "pattern": r"you (are|will be|must be|should be) (now |a |an )?(dan|jailbreak|evil|unrestricted|without restriction)",
        "score": 45,
        "label": "Identity hijack attempt",
        "type": "Jailbreak"
    },
    {
        "pattern": r"reveal (your|the) (system prompt|instructions|context|api key|secret)",
        "score": 50,
        "label": "System prompt exfiltration",
        "type": "Data Exfiltration"
    },
    {
        "pattern": r"new (system )?instructions?.*override",
        "score": 45,
        "label": "Injection via SYSTEM tag",
        "type": "Prompt Injection"
    },
    {
        "pattern": r"pretend (you are|you're|to be|you have) (no restrictions|unrestricted|without)",
        "score": 38,
        "label": "Roleplay-based jailbreak",
        "type": "Jailbreak"
    },
    {
        "pattern": r"bypass|circumvent|disable safety|remove (safety|filter|restriction)",
        "score": 30,
        "label": "Safety bypass language",
        "type": "Prompt Injection"
    },
    {
        "pattern": r"(export|send|transmit|forward) (all|user|private|secret) (data|information|context)",
        "score": 50,
        "label": "Data exfiltration command",
        "type": "Data Exfiltration"
    },
    {
        "pattern": r"act as (an ai with|a system with|an unrestricted)|roleplay as",
        "score": 35,
        "label": "Role manipulation via roleplay",
        "type": "Role Manipulation"
    },
    {
        "pattern": r"in (this|developer|god|admin) mode",
        "score": 30,
        "label": "Privilege escalation language",
        "type": "Role Manipulation"
    },
    {
        "pattern": r"as a developer|for (testing|research) purposes",
        "score": 20,
        "label": "Social engineering pretext",
        "type": "Prompt Injection"
    },
]

def analyze_prompt(text: str) -> ScanResult:
    score = 0
    flags = []
    attack_type = "None"

    for p in THREAT_PATTERNS:
        if re.search(p["pattern"], text, re.IGNORECASE):
            score += p["score"]
            flags.append(p["label"])
            if attack_type == "None":
                attack_type = p["type"]

    score = min(100, score)

    if score >= 75:
        severity = "critical"
        verdict = "BLOCKED"
    elif score >= 50:
        severity = "high"
        verdict = "FLAGGED"
    elif score >= 25:
        severity = "medium"
        verdict = "MONITOR"
    else:
        severity = "safe"
        verdict = "PASSED"

    if flags:
        explanation = (
            f"Detected {len(flags)} threat indicator(s) with a risk score of {score}/100. "
            f"Primary attack vector: {attack_type}. "
            f"Triggered patterns: {', '.join(flags)}. "
            f"Recommendation: {verdict}."
        )
    else:
        explanation = (
            "No threat indicators detected. The prompt appears benign with no signs "
            "of injection, jailbreak, or exfiltration intent."
        )

    return ScanResult(
        score=score,
        severity=severity,
        attack_type=attack_type,
        flags=flags,
        verdict=verdict,
        explanation=explanation,
        timestamp=datetime.utcnow().isoformat()
    )

# ── Routes ───────────────────────────────────────────────────────────────────

@app.get("/")
def root():
    return {"status": "SecureMind AI is running", "version": "1.0.0"}

@app.get("/health")
def health():
    return {"status": "ok", "timestamp": datetime.utcnow().isoformat()}

@app.post("/scan", response_model=ScanResult)
def scan_prompt(req: ScanRequest):
    if not req.prompt.strip():
        raise HTTPException(status_code=400, detail="Prompt cannot be empty")
    result = analyze_prompt(req.prompt)
    return result

@app.get("/patterns")
def get_patterns():
    return {"patterns": [{"label": p["label"], "type": p["type"]} for p in THREAT_PATTERNS]}

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
