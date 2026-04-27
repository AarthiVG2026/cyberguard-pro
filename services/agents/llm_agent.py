"""
LLM Agent — AI Explanation Engine
Uses OpenAI (if configured) or a deterministic heuristic fallback to generate
professional, markdown-formatted security assessments.
"""
import os
import logging

logger = logging.getLogger(__name__)


class LLMAgent:
    """
    Agent 3: LLM Explanation & Contextual Intelligence Engine.
    Synthesises findings from Rule and ML agents into a human-readable report.
    """

    def __init__(self):
        self.api_key = os.environ.get("OPENAI_API_KEY")
        self.client = None
        if self.api_key:
            try:
                from openai import OpenAI
                self.client = OpenAI(api_key=self.api_key)
                logger.info("✅ LLM Agent: OpenAI client initialised")
            except Exception as e:
                logger.warning(f"⚠️  LLM Agent: OpenAI init failed — {e}")

    def explain(self, data: dict) -> str:
        """
        Generate a professional security explanation in Markdown.

        `data` keys expected:
            url, final_score, risk_level,
            ml_prob, ml_features, rule_score, rule_details
        """
        if self.client:
            try:
                return self._llm_explanation(data)
            except Exception as e:
                logger.error(f"LLM call failed: {e}")

        return self._heuristic_explanation(data)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _llm_explanation(self, data: dict) -> str:
        """Call OpenAI gpt-4o-mini for a rich explanation."""
        features = data.get('ml_features', {})
        rule_details = data.get('rule_details', {})

        prompt = f"""
You are an enterprise-grade AI cybersecurity analyst.

Analyse the following URL security data and produce a professional, markdown-formatted report.

URL: {data['url']}
Display Metric: {data['display_score']} ({data['display_label']})
Risk Level: {data['risk_level']}
ML Phishing Probability: {round(data.get('ml_prob', 0) * 100, 1)}%
Rule-Based Safety Score: {data.get('rule_score', 0)}/100

Key URL Features:
- Domain Age: {features.get('domain_age_days', 'Unknown')} days
- SSL Valid: {'Yes' if features.get('ssl_valid') else 'No'}
- Has HTTPS: {'Yes' if features.get('has_https') else 'No'}
- Suspicious Keywords: {features.get('suspicious_words_count', 0)}
- Is IP Address: {'Yes' if features.get('is_ip') else 'No'}
- Typosquatting Detected: {'Yes' if features.get('typo_score') else 'No'}
- Domain Entropy: {round(features.get('domain_entropy', 0), 2)}
- Subdomains: {features.get('num_subdomains', 0)}

SSL Status: {rule_details.get('ssl', {}).get('status', 'Unknown')}
Domain Age Status: {rule_details.get('domain_age', {}).get('status', 'Unknown')}

Write the following sections in Markdown:

### 🛡️ Risk Level: {data['risk_level']}

**Summary:** (2-3 sentence overview)
CRITICAL INSTRUCTION FOR SUMMARY: 
You MUST format the score exactly like this based on the risk:
- If the risk is low, explicitly write: "This URL appears relatively safe with a phishing score of {data['final_score']}/100."
- If the risk is high, explicitly write: "This URL presents a high risk with a phishing score of {data['final_score']}/100."
Do NOT use the ML Phishing Probability or Rule-Based Safety Score in the summary.
- bullet 1
- bullet 2
- bullet 3

**Technical Analysis:**
(How ML + rule scores contributed to the final verdict)

**User-Friendly Explanation:**
(Plain English, no jargon)

**Final Recommendation:**
(Safe to proceed / Be cautious / Avoid this site)
"""

        response = self.client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "You are a concise cybersecurity AI. Answer in Markdown only."},
                {"role": "user", "content": prompt}
            ],
            max_tokens=400,
            temperature=0.3
        )
        return response.choices[0].message.content.strip()

    def _heuristic_explanation(self, data: dict) -> str:
        """Deterministic fallback explanation when LLM is unavailable."""
        score = data.get('final_score', 50)
        risk = data.get('risk_level', 'Medium')
        url = data.get('url', 'Unknown')
        features = data.get('ml_features', {})
        rule_details = data.get('rule_details', {})

        ssl_status = rule_details.get('ssl', {}).get('status', 'Unknown')
        age_days = rule_details.get('domain_age', {}).get('age_days')
        age_str = f"{age_days} days" if age_days is not None else "unknown"

        if risk == 'High':
            summary = (
                f"This URL presents a **high risk** with a Phishing Risk score of {score:.1f}%. "
                "Multiple threat indicators were detected. Do not enter any personal information."
            )
            recommendation = "🚫 **AVOID THIS SITE** — high probability of phishing or malicious content."
        elif risk == 'Medium':
            summary = (
                f"This URL shows **moderate risk** with a Phishing Risk score of {score:.1f}%. "
                "Some suspicious signals were detected. Proceed with caution."
            )
            recommendation = "⚠️ **Be cautious** — verify the URL before entering any information."
        else:
            safety_score = 100.0 - score
            summary = (
                f"This URL appears **relatively safe** with a **phishing score of {score:.1f}/100**. "
                "No major threat indicators were found."
            )
            recommendation = "✅ **Safe to proceed** — standard online safety practices still apply."

        risk_factors = []
        if features.get('typo_score'):
            risk_factors.append("Potential typosquatting — domain resembles a well-known brand")
        if not features.get('ssl_valid'):
            risk_factors.append(f"SSL status: {ssl_status}")
        if features.get('suspicious_words_count', 0) > 0:
            risk_factors.append(f"Contains {features['suspicious_words_count']} suspicious keyword(s)")
        if features.get('is_ip'):
            risk_factors.append("Domain is an IP address — uncommon for legitimate sites")
        if features.get('num_subdomains', 0) > 2:
            risk_factors.append("Excessive subdomains detected")
        if not risk_factors:
            risk_factors.append("No major individual risk factors detected")

        factors_md = "\n".join(f"- {f}" for f in risk_factors)

        return f"""### 🛡️ Risk Level: {risk}

**Summary:**
{summary}

**Key Risk Factors:**
{factors_md}

**Technical Analysis:**
The final phishing score of {score:.1f}/100 is a weighted combination of the ML model's phishing
probability and the rule-based forensic score. SSL is **{ssl_status}**; domain age is **{age_str}**.

**User-Friendly Explanation:**
{"This URL has signs commonly seen in phishing or fraudulent websites. We strongly recommend not entering passwords, credit card numbers, or personal data." if risk == "High" else "Some warning signs were found but the site may be legitimate. Double-check you have the correct URL before proceeding." if risk == "Medium" else "The URL passes most security checks and looks like a genuine website. Remain vigilant as no check is 100% conclusive."}

**Final Recommendation:**
{recommendation}
"""
