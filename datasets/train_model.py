import pandas as pd
import joblib
from xgboost import XGBClassifier
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report, recall_score
from collections import Counter
import os

def train_professional_model():
    print("--- Phase 7: Training Ultra-Precision Ensemble Model (40 Features) ---")
    
    # 1. Load the optimized dataset
    # Look in the correct datasets folder relative to the script
    data_path = os.path.join(os.path.dirname(__file__), "datasets", "featured_40_dataset.csv")
    if not os.path.exists(data_path):
        print(f"Error: {data_path} not found!")
        return

    print(f"Loading dataset: {data_path}...")
    df = pd.read_csv(data_path)
    
    # 2. Separate Features (X) and Labels (y)
    X = df.drop('target', axis=1)
    y = df['target']
    
    # 3. Train/Test Split
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.15, random_state=42)

    # 4. Phase 8: Ensemble of Experts
    print("\nTraining Ensemble Model (XGBoost + Random Forest)...")
    
    counts = Counter(y_train)
    scale_pos = counts[0] / counts[1] if counts[1] > 0 else 1
    
    # Model A: Deep XGBoost
    xgb = XGBClassifier(
        n_estimators=1500,
        max_depth=12,
        learning_rate=0.01,
        subsample=0.8,
        colsample_bytree=0.8,
        scale_pos_weight=scale_pos,
        eval_metric='logloss',
        random_state=42,
        n_jobs=-1
    )
    
    # Model B: Robust Random Forest
    rf = RandomForestClassifier(
        n_estimators=500,
        max_depth=25,
        min_samples_split=5,
        random_state=42,
        n_jobs=-1
    )
    
    # Combine into Voting Classifier
    ensemble = VotingClassifier(
        estimators=[('xgb', xgb), ('rf', rf)],
        voting='soft', # Use probabilities for voting
        weights=[1.5, 1] # Give slightly more weight to XGBoost
    )
    
    print("Fitting ensemble (this may take 1-2 minutes)...")
    ensemble.fit(X_train, y_train)
    
    # 5. Evaluate
    y_pred = ensemble.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    recall = recall_score(y_test, y_pred)
    
    print(f"\nUltra-Ensemble Performance (40 Features / {len(df)} Samples):")
    print(f"Overall Accuracy: {acc * 100:.4f}%")
    print(f"Phishing Recall: {recall * 100:.4f}%")
    print("\nDetailed Classification Report:")
    print(classification_report(y_test, y_pred))

    # 6. Save the model
    # Save in the script's directory
    model_path = os.path.join(os.path.dirname(__file__), 'phishing_model.pkl')
    joblib.dump(ensemble, model_path)
    print(f"\nSuccess: Ultra-Precision ensemble model saved as {model_path}")

if __name__ == "__main__":
    train_professional_model()
