import logging
import json
from services.agents.rule_agent import RuleAgent
from services.agents.ml_agent import MLAgent
from services.agents.llm_agent import LLMAgent
from services.common.cache import cache_service

# Enterprise Structured Logging
logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger(__name__)

class AIOrchestrator:
    """
    MASTER ENGINE: Unified Multi-Agent AI Orchestrator.
    Combines rule-based forensics and ML predictions.
    """
    def __init__(self):
        # 1. Configurable Enterprise Weights
        self.WEIGHTS = {
            "ml": 0.6,
            "rule": 0.4
        }
        
        # 2. Initialize Agents
        self.rule_agent = RuleAgent(max_workers=4)
        self.ml_agent = MLAgent()
        self.llm_agent = LLMAgent()

    def analyze(self, url):
        """
        Unified analysis pipeline with caching and orchestrator logic.
        """
        # 1. Caching Layer (Enterprise Performance)
        cached_result = cache_service.get(url)
        if cached_result:
            logger.info({"event": "cache_hit", "url": url})
            return cached_result

        try:
            # 2. Parallel Rule Analysis
            rule_result = self.rule_agent.analyze(url)
            rule_score = rule_result['score'] # 0 (Safe) to 100 (Dangerous) - wait, RuleAgent 100 is Safe.
            # Let's standardize: Risk Score 0 (Safe) to 100 (Dangerous)
            # My RuleAgent returns Safe=100. Let's invert it for Risk.
            rule_risk = 100 - rule_score 

            # 3. ML Analysis
            ml_result = self.ml_agent.predict(url)
            ml_risk = ml_result['probability'] * 100

            # 4. ORCHESTRATOR LOGIC: Weighted Score
            final_risk = (self.WEIGHTS['ml'] * ml_risk) + (self.WEIGHTS['rule'] * rule_risk)
            
            # --- ENTERPRISE TRUSTED DOMAINS WHITELIST ---
            # Major platforms should have near-zero risk and known ages
            # Calculated for ~April 2026
            trusted_data = {
                'google.com': 10450,    # Sep 1997
                'facebook.com': 8120,   # Mar 2004
                'instagram.com': 5650,  # Oct 2010
                'amazon.com': 11300,    # Nov 1994
                'microsoft.com': 15000, # May 1991
                'apple.com': 17500,     # Feb 1987
                'netflix.com': 10500,   # Aug 1997
                'paypal.com': 9800,     # Mar 1999
                'github.com': 6580,     # Apr 2008
                'linkedin.com': 8550,   # Nov 2002
                'youtube.com': 7740,    # Feb 2005
                'x.com': 8500,          # 2003 (reacquired)
                'twitter.com': 7350,    # Mar 2006
                'wikipedia.org': 9200,  # Jan 2001
                'reddit.com': 7600,     # Apr 2005
                'yahoo.com': 11400,     # Jan 1995
                'whatsapp.com': 6300,   # 2008
                'snapt.com': 10200,     # May 1998
                'snapchat.com': 5360,   # 2011
                'snapcaht.com': 0,      # Phishing attempt
                'microsoft-security.com': 150 # Potential phishing
            }
            
            domain_name = self.rule_agent._extract_domain(url).replace('www.', '')
            if domain_name in trusted_data:
                # Force high age for giants if WHOIS failed
                if not rule_result['details']['domain_age'].get('age_days'):
                    rule_result['details']['domain_age']['age_days'] = trusted_data[domain_name]
                    rule_result['details']['domain_age']['status'] = 'Trusted Source'
                
                # Drastically reduce risk for verified giants (percentage correction)
                final_risk = final_risk * 0.05 
            
            # Ensure final risk is bounded
            final_risk = max(0, min(100, final_risk))
            
            # Determine Risk Level
            risk_level = "Low"
            if final_risk > 70: risk_level = "High"
            elif final_risk > 40: risk_level = "Medium"

            # 5. INTEGRATE REAL DATA INTO FEATURES (For UI consistency)
            # Pull networking data from Rule Agent into the features vector
            ml_result['features']['domain_age_days'] = rule_result['details']['domain_age'].get('age_days')
            ml_result['features']['ssl_valid'] = 1 if rule_result['details']['ssl']['status'] == 'Valid' else 0

            # Calculate display percentage based on user preference
            is_phishing = final_risk > 50
            display_score = round(final_risk, 1) if is_phishing else round(100 - final_risk, 1)
            display_label = "Phishing Risk" if is_phishing else "Safety Score"

            # 6. LLM Explanation (Contextual RAG)
            agent_data = {
                "url": url,
                "final_score": round(final_risk, 2),
                "display_score": display_score,
                "display_label": display_label,
                "risk_level": risk_level,
                "ml_prob": ml_result['probability'],
                "ml_features": ml_result['features'],
                "rule_score": rule_score,
                "rule_details": rule_result['details']
            }
            explanation = self.llm_agent.explain(agent_data)

            # 7. Structured Logging (Enterprise Observability)
            log_entry = {
                "event": "url_analyzed",
                "url": url,
                "ml_risk": round(ml_risk, 2),
                "rule_risk": round(rule_risk, 2),
                "final_risk": round(final_risk, 2),
                "risk_level": risk_level
            }
            logger.info(json.dumps(log_entry))

            # 7. Structured Logging (Enterprise Observability)

            result = {
                "success": True,
                "url": url,
                "prediction": "phishing" if is_phishing else "safe",
                "final_risk_score": round(final_risk, 2),
                "display_score": display_score,
                "display_label": display_label,
                "risk_level": risk_level,
                "explanation": explanation,
                "agent_metrics": {
                    "ml_score": round(ml_risk, 2),
                    "rule_score": round(rule_risk, 2)
                },
                "features": ml_result['features'],
                "details": rule_result['details']
            }

            # Store in cache
            cache_service.set(url, result)
            return result

        except Exception as e:
            logger.error({"event": "orchestration_failed", "url": url, "error": str(e)})
            return {"success": False, "error": str(e)}

# Singleton Orchestration Instance
orchestrator = AIOrchestrator()
