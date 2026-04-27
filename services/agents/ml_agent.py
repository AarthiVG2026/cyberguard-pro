"""
ML Agent — Machine Learning Phishing Prediction Agent
Wraps the trained Random Forest model and the FeatureExtractor pipeline.
"""
import os
import pickle
import logging
import numpy as np

from services.common.feature_extractor import FeatureExtractor

logger = logging.getLogger(__name__)


class MLAgent:
    """
    Agent 2: Machine Learning Prediction Engine.
    Uses a pre-trained Random Forest model to predict phishing probability.
    Falls back to heuristic scoring if model is not available.
    """

    def __init__(self, model_path='ml_models/phishing_rf_model.pkl'):
        self.model = None
        self.feature_extractor = FeatureExtractor()
        self.feature_names = self.feature_extractor.get_feature_names()

        # Try loading model relative to the project root
        base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        full_path = os.path.join(base_dir, model_path)

        if os.path.exists(full_path):
            try:
                with open(full_path, 'rb') as f:
                    self.model = pickle.load(f)
                logger.info(f"✅ ML model loaded from {full_path}")
            except Exception as e:
                logger.warning(f"⚠️  Failed to load ML model: {e}")
        else:
            logger.warning(f"⚠️  ML model not found at {full_path} — using heuristic fallback")

    def predict(self, url: str) -> dict:
        """
        Predict phishing probability for a URL.
        Returns:
            {
                'prediction': 'phishing' | 'safe',
                'probability': float (0.0 – 1.0),
                'features': dict,
            }
        """
        features_dict = self.feature_extractor.extract_features(url)
        feature_vector = np.array([[features_dict[name] for name in self.feature_names]])

        if self.model is not None:
            try:
                proba = self.model.predict_proba(feature_vector)[0]
                phishing_prob = float(proba[1])
            except Exception as e:
                logger.error(f"Model prediction error: {e}")
                phishing_prob = self._heuristic_probability(features_dict)
        else:
            phishing_prob = self._heuristic_probability(features_dict)

        # Apply weighted risk adjustments
        risk = phishing_prob
        if features_dict.get('typo_score') == 1:
            risk = max(risk, 0.7) + 0.25
        if features_dict.get('ssl_valid') == 0:
            risk += 0.10
        if features_dict.get('domain_age_days', 0) < 30:
            risk += 0.15
        risk += features_dict.get('suspicious_words_count', 0) * 0.05

        # Trust boost for old, clean domains
        if risk < 0.1 and features_dict.get('domain_age_days', 0) > 1000 and features_dict.get('ssl_valid') == 1:
            risk = 0.001

        phishing_prob = max(0.0, min(0.999, risk))
        prediction = 'phishing' if phishing_prob >= 0.5 else 'safe'

        return {
            'prediction': prediction,
            'probability': phishing_prob,
            'features': features_dict,
        }

    def _heuristic_probability(self, features: dict) -> float:
        """Rule-based fallback when model is unavailable."""
        risk = 0.0
        if features.get('has_https') == 0:
            risk += 0.20
        if features.get('num_subdomains', 0) >= 2:
            risk += 0.30
        if features.get('is_ip') == 1:
            risk += 0.60
        if features.get('suspicious_words_count', 0) > 0:
            risk += 0.40
        if features.get('url_length', 0) > 75:
            risk += 0.10
        if features.get('num_hyphens', 0) >= 2:
            risk += 0.20
        if features.get('typo_score') == 1:
            risk += 0.50
        if features.get('domain_entropy', 0) > 4.2:
            risk += 0.30
        if features.get('domain_age_days', 0) < 30:
            risk += 0.40
        return min(1.0, risk)
