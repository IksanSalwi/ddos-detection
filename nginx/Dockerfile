FROM nginx:1.25-alpine

# Install required modules
RUN apk add --no-cache nginx-mod-http-geoip

# Copy custom configuration
COPY nginx.conf /etc/nginx/nginx.conf
COPY log_format.json /etc/nginx/log_format.json

# Create log directory
RUN mkdir -p /var/log/nginx

EXPOSE 80