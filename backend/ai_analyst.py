"""
PhishGuard Cloud - AI Threat Intelligence Analyst
Provides Explainable AI (XAI) security intelligence using Google Gemini API
with an offline expert heuristic engine fallback.
"""

import os
import json
import urllib.request
from urllib.parse import urlparse


def call_gemini_api(prompt, api_key):
    """Call Google Gemini REST API without external dependencies."""
    endpoint = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={api_key}"
    headers = {"Content-Type": "application/json"}
    payload = {
        "contents": [{
            "parts": [{"text": prompt}]
        }],
        "generationConfig": {
            "temperature": 0.2,
            "maxOutputTokens": 200
        }
    }
    
    try:
        req = urllib.request.Request(
            endpoint,
            data=json.dumps(payload).encode("utf-8"),
            headers=headers,
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=5) as response:
            result = json.loads(response.read().decode("utf-8"))
            candidates = result.get("candidates", [])
            if candidates:
                text = candidates[0].get("content", {}).get("parts", [{}])[0].get("text", "")
                return text.strip()
    except Exception as e:
        print("Gemini API fallback triggered:", e)
    return None


def generate_ai_analysis(url, scan_result):
    """Generate concise Explainable AI threat intelligence for scanned URLs."""
    status = scan_result.get("status", "SAFE")
    risk_score = scan_result.get("risk_score", 0)
    reasons = scan_result.get("reasons", [])
    ml_pred = scan_result.get("ml_prediction", "SAFE")
    ml_prob = scan_result.get("ml_probability", 0.0)
    
    parsed = urlparse(url if "://" in url else "https://" + url)
    domain = parsed.hostname or url
    
    # Check if live Gemini API key is available
    api_key = os.environ.get("GEMINI_API_KEY")
    if api_key:
        prompt = (
            f"You are a Cybersecurity Analyst for PhishGuard Cloud. "
            f"Analyze this URL: {url}. Verdict: {status}, Risk Score: {risk_score}%, "
            f"ML Prediction: {ml_pred} ({ml_prob}%), Detected Signals: {', '.join(reasons) if reasons else 'None'}. "
            f"Provide a 2-sentence threat intelligence summary explaining whether this is safe or dangerous, "
            f"identifying the attack vector if malicious (e.g. credential harvesting, lookalike domain, brand impersonation), "
            f"and giving a concrete safety recommendation."
        )
        gemini_summary = call_gemini_api(prompt, api_key)
        if gemini_summary:
            return {
                "source": "Google Gemini 1.5 Flash (Live AI)",
                "summary": gemini_summary,
                "risk_badge": status,
                "action": "Proceed with confidence" if status == "SAFE" else "Do not provide credentials or personal details"
            }

    # Autonomous Expert Neural Engine Fallback
    summary_parts = []
    action = "Safe to visit"
    
    if status == "PHISHING":
        summary_parts.append(
            f"PhishGuard AI detected high-confidence deception patterns on {domain}. "
        )
        if any("Brand impersonation" in r for r in reasons):
            summary_parts.append(
                "The site mimics a reputable brand on an unverified third-party host to mislead visitors. "
            )
        elif any("IP address" in r for r in reasons):
            summary_parts.append(
                "Direct IP hosting without domain validation indicates a typical ephemeral phishing server. "
            )
        else:
            summary_parts.append(
                f"Statistical feature analysis confirms anomalous structural characteristics ({ml_prob}% probability). "
            )
        action = "CRITICAL: Block access immediately. Do not enter credentials or download files."

    elif status == "SUSPICIOUS":
        summary_parts.append(
            f"PhishGuard AI flagged {domain} with caution signals (Risk: {risk_score}%). "
        )
        if any("Typosquatting" in r for r in reasons):
            summary_parts.append(
                "Domain employs typographical permutations resembling an established brand (Lookalike Domain). "
            )
        elif any("Brand impersonation" in r for r in reasons):
            summary_parts.append(
                "Brand identifier detected on a non-authoritative host. "
            )
        elif any(".invalid" in r for r in reasons):
            summary_parts.append(
                "Domain utilizes an unverified or reserved suffix. "
            )
        else:
            summary_parts.append(
                "URL structure exhibits elevated entropy and risk indicators. "
            )
        action = "WARNING: Exercise extreme caution. Verify destination identity before entering information."

    else:
        if scan_result.get("is_trusted"):
            summary_parts.append(
                f"PhishGuard AI verified that {domain} is an authenticated official application service. "
            )
        else:
            summary_parts.append(
                f"PhishGuard AI verified that {domain} adheres to legitimate web conventions with no suspicious lexical markers. "
            )
        action = "VERIFIED: Safe to navigate."

    return {
        "source": "PhishGuard Neural Intelligence (XAI)",
        "summary": "".join(summary_parts),
        "risk_badge": status,
        "action": action
    }
