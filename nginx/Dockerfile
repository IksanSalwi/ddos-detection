FROM mirror.gcr.io/nginx:1.25-alpine

# Copy custom configuration
COPY nginx.conf /etc/nginx/nginx.conf
COPY log_format.json /etc/nginx/log_format.json

# Create log directory
RUN mkdir -p /var/log/nginx

EXPOSE 80