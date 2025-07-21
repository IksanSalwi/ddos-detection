import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.preprocessing import StandardScaler
import time
import joblib
import json
import os
import warnings
warnings.filterwarnings("ignore")

def retrain_and_export_model(dataset_path='dataset_sdn.csv'):
    # Load the dataset
    data = pd.read_csv(dataset_path)
    data = data.dropna()

    # Select important features
    important_features = [
        'pktcount', 'byteperflow', 'tot_kbps', 'rx_kbps',
        'flows', 'bytecount', 'Protocol', 'tot_dur', 'label'
    ]
    df = data[important_features]

    # One-hot encode Protocol
    X = pd.get_dummies(df.drop('label', axis=1), prefix='Protocol')
    y = df['label']

    # Save feature names and encoding info
    feature_names = {
        "selected_features": important_features[:-1],
        "encoded_features": list(X.columns)
    }
    with open('feature_names.json', 'w') as f:
        json.dump(feature_names, f, indent=4)

    # Standardize features
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # Save scaler
    joblib.dump(scaler, 'scaler.pkl')

    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X_scaled, y, test_size=0.3, random_state=42
    )

    # Train RandomForest model
    model = RandomForestClassifier(n_estimators=500, max_depth=16, random_state=42, n_jobs=-1)
    model.fit(X_train, y_train)

    # Evaluate model
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    print(f"Model accuracy: {accuracy:.4f}")
    print(classification_report(y_test, y_pred))

    # Save model
    joblib.dump(model, 'ddos_detection_model.pkl')

    print("Model, scaler, and feature names saved successfully.")

if __name__ == "__main__":
    retrain_and_export_model()
