import pandas as pd
import numpy as np
import joblib
import json
import os
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, precision_score, recall_score, f1_score

def load_artifacts(model_dir='model'):
    model = joblib.load(os.path.join(model_dir, 'ddos_detection_model.pkl'))
    scaler = joblib.load(os.path.join(model_dir, 'scaler.pkl'))
    with open(os.path.join(model_dir, 'feature_names.json')) as f:
        feature_info = json.load(f)
    return model, scaler, feature_info

def preprocess_data(data_path, feature_info):
    data = pd.read_csv(data_path)
    data = data.dropna()

    # One-hot encode Protocol
    X = pd.get_dummies(data.drop('label', axis=1), prefix='Protocol')

    # Ensure all encoded features are present in the dataframe
    for col in feature_info['encoded_features']:
        if col not in X.columns:
            X[col] = 0

    # Reorder columns to match the model's expected input
    X = X[feature_info['encoded_features']]

    y = data['label']

    return X, y

def evaluate_model():
    model, scaler, feature_info = load_artifacts()
    X, y = preprocess_data('dataset_sdn.csv', feature_info)

    # Scale features
    X_scaled = scaler.transform(X)

    # Predict
    y_pred = model.predict(X_scaled)

    # Calculate metrics
    accuracy = accuracy_score(y, y_pred)
    precision = precision_score(y, y_pred)
    recall = recall_score(y, y_pred)
    f1 = f1_score(y, y_pred)
    conf_matrix = confusion_matrix(y, y_pred)
    class_report = classification_report(y, y_pred)

    print("Model Evaluation Metrics:")
    print(f"Accuracy:  {accuracy:.4f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall:    {recall:.4f}")
    print(f"F1 Score:  {f1:.4f}")
    print("\nConfusion Matrix:")
    print(conf_matrix)
    print("\nClassification Report:")
    print(class_report)

if __name__ == "__main__":
    evaluate_model()
