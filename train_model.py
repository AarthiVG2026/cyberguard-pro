import os
import random
import pickle
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
from ml_service import FeatureExtractor

def generate_synthetic_features(num_samples=10000):
    """Generate synthetic features directly to control signal strength."""
    features_list = []
    labels = []
    
    for _ in range(num_samples // 2):
        # Safe URL Features
        f = {
            'url_length': random.randint(15, 40),
            'domain_length': random.randint(8, 15),
            'num_dots': random.randint(1, 2),
            'num_subdomains': random.randint(0, 1),
            'is_ip': 0,
            'has_https': 1,
            'ssl_valid': 1,
            'suspicious_words_count': 0,
            'num_hyphens': random.randint(0, 1),
            'num_digits': random.randint(0, 2),
            'contains_at': 0,
            'domain_entropy': random.uniform(2.5, 3.8),
            'typo_score': 0,
            'domain_age_days': random.randint(365, 5000)
        }
        features_list.append(f)
        labels.append(0) # safe
        
    for _ in range(num_samples // 2):
        # Phishing URL Features
        is_typo = 1 if random.random() > 0.5 else 0
        is_new = 1 if random.random() > 0.7 else 0
        has_suspicious_words = 1 if random.random() > 0.4 else 0
        
        f = {
            'url_length': random.randint(30, 100),
            'domain_length': random.randint(10, 30),
            'num_dots': random.randint(2, 5),
            'num_subdomains': random.randint(1, 4),
            'is_ip': 1 if random.random() > 0.9 else 0,
            'has_https': 1 if random.random() > 0.5 else 0,
            'ssl_valid': 0 if random.random() > 0.3 else 1,
            'suspicious_words_count': random.randint(1, 4) if has_suspicious_words else 0,
            'num_hyphens': random.randint(1, 5),
            'num_digits': random.randint(2, 10),
            'contains_at': 1 if random.random() > 0.9 else 0,
            'domain_entropy': random.uniform(3.5, 5.0),
            'typo_score': is_typo,
            'domain_age_days': random.randint(1, 30) if is_new else random.randint(30, 365)
        }
        
        # KEY FIX: If it's a typo, it's FISHY even if it's old (parked domains/long-term squatters)
        if is_typo:
            # 30% of typos are old parked domains
            if random.random() > 0.7:
                f['domain_age_days'] = random.randint(1000, 8000)
            else:
                f['domain_age_days'] = random.randint(1, 100)
            f['has_https'] = 1 if random.random() > 0.3 else 0 
            
        features_list.append(f)
        labels.append(1) # phishing
        
    return pd.DataFrame(features_list), labels

def train_and_evaluate():
    print("Generating high-signal synthetic features...")
    X, y = generate_synthetic_features(10000)
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    print("Training Robust Random Forest Classifier...")
    # Increase n_estimators and depth for better nuance
    model = RandomForestClassifier(n_estimators=200, max_depth=15, random_state=42)
    model.fit(X_train, y_train)
    
    print("Evaluating Model Accuracy and Precision...")
    y_pred = model.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    print(f"Accuracy: {acc*100:.2f}%")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=['Safe', 'Phishing']))
    
    # Save the model
    os.makedirs('ml_models', exist_ok=True)
    model_path = 'ml_models/phishing_rf_model.pkl'
    
    with open(model_path, 'wb') as f:
        pickle.dump(model, f)
        
    print(f"Proprietary Model saved successfully to {model_path}!")

if __name__ == "__main__":
    train_and_evaluate()
