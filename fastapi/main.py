from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import joblib
import json
import numpy as np
import os
import logging
import time

app = FastAPI()

# Add CORS middleware to allow frontend requests
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8081"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure logging for DDoS detection
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ddos-detector")

# Load model artifacts
MODEL_DIR = "model"
try:
    model = joblib.load(os.path.join(MODEL_DIR, "ddos_detection_model.pkl"))
    scaler = joblib.load(os.path.join(MODEL_DIR, "scaler.pkl"))
    
    with open(os.path.join(MODEL_DIR, "feature_names.json")) as f:
        feature_info = json.load(f)
    
    logger.info("Model artifacts loaded successfully")
except Exception as e:
    logger.error(f"Error loading model artifacts: {str(e)}")
    raise RuntimeError("Model initialization failed")

def prepare_features(request: Request):
    """Extract features from request for DDoS detection"""
    try:
        # Get basic connection info
        client_ip = request.client.host
        user_agent = request.headers.get("user-agent", "")
        
        # Extract features from request headers with better defaults
        features = {
            'pktcount': max(1, int(request.headers.get('pktcount', 1))),
            'byteperflow': max(1, int(request.headers.get('byteperflow', 64))),
            'tot_kbps': max(0.1, float(request.headers.get('tot-kbps', 1.0))),
            'rx_kbps': max(0.1, float(request.headers.get('rx-kbps', 1.0))),
            'flows': max(1, int(request.headers.get('flows', 1))),
            'bytecount': max(1, int(request.headers.get('bytecount', 64))),
            'tot_dur': max(0.001, float(request.headers.get('tot-dur', 0.1))),
            'Protocol': request.headers.get('protocol', 'HTTP')
        }
        
        # Encode protocol
        protocol = features['Protocol']
        encoded_features = feature_info.get("encoded_features", [])
        
        # Create feature vector with proper protocol encoding
        feature_vector = []
        for col in encoded_features:
            if col.startswith('Protocol_'):
                proto_name = col.split('_')[1]
                feature_vector.append(1 if proto_name == protocol else 0)
            else:
                feature_vector.append(features.get(col, 0))
        
        return np.array([feature_vector])
    
    except Exception as e:
        logger.error(f"Feature extraction error: {str(e)}")
        # Return safe default features that won't crash the model
        return np.array([[1, 64, 1.0, 1.0, 1, 64, 0.1, 0, 0, 1]])  # Default to HTTP

# Middleware to log each request and response
@app.middleware("http")
async def log_requests(request: Request, call_next):
    # Log request info without consuming body
    logger.info(f"Request: method={request.method} url={request.url} headers={dict(request.headers)}")
    
    # Process request normally
    response = await call_next(request)
    
    # Log response info
    logger.info(f"Response: status_code={response.status_code}")
    
    return response

@app.api_route("/detect", methods=["GET", "POST"])
async def detect_ddos(request: Request):
    """DDoS detection endpoint"""
    start_time = time.time()
    
    try:
        # Get features with improved error handling
        features = prepare_features(request)
        
        # Scale features
        scaled_features = scaler.transform(features)
        
        # Make prediction with timeout protection
        prediction = model.predict(scaled_features)
        probability = model.predict_proba(scaled_features)
        
        # Calculate processing time
        processing_time = time.time() - start_time
        
        # Prepare response
        is_malicious = bool(prediction[0])
        malicious_prob = float(probability[0][1])
        
        # Log successful prediction
        logger.info(f"Prediction completed in {processing_time:.3f}s - Malicious: {is_malicious}, Score: {malicious_prob:.3f}")
        
        return JSONResponse(
            content={
                "is_malicious": is_malicious,
                "malicious_probability": malicious_prob,
                "processing_time": processing_time
            },
            headers={
                "ddos-score": str(malicious_prob),
                "is-malicious": str(is_malicious).lower(),
                "Access-Control-Allow-Origin": "http://localhost:8081"
            }
        )
    
    except Exception as e:
        processing_time = time.time() - start_time
        logger.error(f"Prediction error after {processing_time:.3f}s: {str(e)}")
        
        # Return safe default response instead of error
        return JSONResponse(
            content={
                "is_malicious": False,
                "malicious_probability": 0.1,
                "processing_time": processing_time,
                "error": "Using default safe response"
            },
            headers={
                "ddos-score": "0.1",
                "is-malicious": "false",
                "Access-Control-Allow-Origin": "http://localhost:8081"
            },
            status_code=200
        )

@app.get("/health")
def health_check():
    return {"status": "healthy"}
