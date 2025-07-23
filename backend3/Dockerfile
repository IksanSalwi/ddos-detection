FROM mirror.gcr.io/nginx:alpine

COPY index.html /usr/share/nginx/html/index.html

# Add server identifier header
RUN echo "add_header X-Backend-Server 'server3' always;" > /etc/nginx/conf.d/server-id.conf

EXPOSE 80