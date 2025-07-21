FROM python:3.9-slim

WORKDIR /app

# Install dependencies
RUN apt-get update && apt-get install -y gcc libssl-dev

COPY requirements.txt .

# Force reinstall numpy and scikit-learn to fix broken installs
RUN pip install --no-cache-dir --force-reinstall numpy==1.26.0 scikit-learn==1.6.1
RUN pip install --no-cache-dir -r requirements.txt

# Copy application and model
COPY . .
COPY model/ model/

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]
