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

 # from fastapi.request_logger import log_request_response

# app.middleware("http")(log_request_response)

# Configure logging berfungsi untuk membaca log dan mendeteksi serangan
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
        
        # Extract features from request
        features = {
            'pktcount': int(request.headers.get('pktcount', 0)),
            'byteperflow': int(request.headers.get('byteperflow', 0)),
            'tot_kbps': float(request.headers.get('tot-kbps', 0.0)),
            'rx_kbps': float(request.headers.get('rx-kbps', 0.0)),
            'flows': int(request.headers.get('flows', 0)),
            'bytecount': int(request.headers.get('bytecount', 0)),
            'tot_dur': float(request.headers.get('tot-dur', 0.0)),
            'Protocol': request.headers.get('protocol', 'HTTP')
        }
        
        # Encode protocol
        protocol = features['Protocol']
        for col in feature_info["encoded_features"]:
        
                proto_name = col.split('_')[1]
                features[col] = 1 if proto_name == protocol else 0
        
        # Create input array in correct feature order
        ordered_features = [features[col] for col in feature_info["encoded_features"]]
        return np.array([ordered_features])
    
    except Exception as e:
        logger.error(f"Feature extraction error: {str(e)}")
        return None

# Middleware to log each request and response
@app.middleware("http")
async def log_requests(request: Request, call_next):
    request_body = await request.body()
    logger.info(f"Request: method={request.method} url={request.url} headers={dict(request.headers)} body={request_body.decode('utf-8', errors='ignore')}")
    response = await call_next(request)
    response_body = b""
    async for chunk in response.body_iterator:
        response_body += chunk
    logger.info(f"Response: status_code={response.status_code} body={response_body.decode('utf-8', errors='ignore')}")
    # Recreate response with original body
    from starlette.responses import Response
    return Response(content=response_body, status_code=response.status_code, headers=dict(response.headers), media_type=response.media_type)
@app.get("/detect")
async def detect_probe():
    """Simple GET handler for Nginx auth_request health check"""
    return JSONResponse(content={"status": "ok"}, headers={"Access-Control-Allow-Origin": "http://localhost:8081"})

@app.post("/detect")
async def detect_ddos(request: Request):
    """DDoS detection endpoint"""
    start_time = time.time()
    
    # Save request data to JSON file
    try:
        body = await request.body()
        request_data = body.decode('utf-8')
        log_file = "request_logs.json"
        # Append request data as a JSON object to the file
        with open(log_file, "a") as f:
            f.write(request_data + "\n")
    except Exception as e:
        logger.error(f"Failed to log request data: {str(e)}")
    
    # Prepare features
    features = prepare_features(request)
    if features is None:
        raise HTTPException(status_code=400, detail="Invalid request features")
    
    try:
        # Scale features
        scaled_features = scaler.transform(features)
        
        # Make prediction
        prediction = model.predict(scaled_features)
        probability = model.predict_proba(scaled_features)
        
        # Calculate processing time
        processing_time = time.time() - start_time
        
        # Prepare response
        is_malicious = bool(prediction[0])
        malicious_prob = float(probability[0][1])
        
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
        logger.error(f"Prediction error: {str(e)}")
        raise HTTPException(status_code=500, detail="Prediction failed")

@app.get("/health")
def health_check():
    return {"status": "healthy"}
