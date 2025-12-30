# ASE Deployment Guide 🚀

This guide covers deploying the ASE (Attack Simulation Engine) application to various platforms.

## Table of Contents
- [Local Development](#local-development)
- [Streamlit Cloud](#streamlit-cloud-recommended)
- [Docker Deployment](#docker-deployment)
- [VPS/Server Deployment](#vpsserver-deployment)
- [Security Considerations](#security-considerations)

---

## Local Development

### Setup

1. **Clone and Install**
```bash
git clone https://github.com/yourusername/ase-security-platform.git
cd ase-security-platform
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

2. **Configure Environment**
```bash
cp .env.example .env
# Edit .env with your actual values
```

3. **Run**
```bash
streamlit run app.py
```

Access at: `http://localhost:8501`

---

## Streamlit Cloud (Recommended)

Streamlit Cloud offers free hosting for Streamlit apps.

### Prerequisites
- GitHub account
- Streamlit Cloud account (free at [streamlit.io/cloud](https://streamlit.io/cloud))

### Deployment Steps

1. **Push to GitHub**
```bash
git init
git add .
git commit -m "Initial commit"
git remote add origin https://github.com/yourusername/ase-security-platform.git
git push -u origin main
```

2. **Deploy on Streamlit Cloud**
   - Go to [share.streamlit.io](https://share.streamlit.io)
   - Click "New app"
   - Select your repository
   - Set main file path: `app.py`
   - Click "Deploy"

3. **Configure Secrets**
   - In Streamlit Cloud dashboard, go to your app settings
   - Click "Secrets"
   - Add your environment variables:
   ```toml
   GEMINI_API_KEY = "your_api_key_here"
   ADMIN_ACCESS_CODE = "your_secure_code_here"
   ```

4. **Access Your App**
   - Your app will be available at: `https://yourusername-ase-security-platform.streamlit.app`

### Limitations
- Free tier: 1 GB RAM, limited CPU
- Public apps only (unless on paid plan)
- No Nmap support (requires system packages)

---

## Docker Deployment

### Create Dockerfile

Create `Dockerfile` in project root:

```dockerfile
FROM python:3.10-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    nmap \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY . .

# Expose Streamlit port
EXPOSE 8501

# Health check
HEALTHCHECK CMD curl --fail http://localhost:8501/_stcore/health

# Run the application
ENTRYPOINT ["streamlit", "run", "app.py", "--server.port=8501", "--server.address=0.0.0.0"]
```

### Build and Run

```bash
# Build image
docker build -t ase-security-platform .

# Run container
docker run -p 8501:8501 \
  -e GEMINI_API_KEY="your_api_key" \
  -e ADMIN_ACCESS_CODE="your_admin_code" \
  ase-security-platform
```

### Docker Compose

Create `docker-compose.yml`:

```yaml
version: '3.8'

services:
  ase-app:
    build: .
    ports:
      - "8501:8501"
    environment:
      - GEMINI_API_KEY=${GEMINI_API_KEY}
      - ADMIN_ACCESS_CODE=${ADMIN_ACCESS_CODE}
    volumes:
      - ./data:/app/data
    restart: unless-stopped
```

Run with:
```bash
docker-compose up -d
```

---

## VPS/Server Deployment

### Requirements
- Ubuntu 20.04+ or similar Linux distribution
- Python 3.8+
- Nginx (for reverse proxy)
- SSL certificate (Let's Encrypt recommended)

### Step-by-Step Setup

#### 1. Install Dependencies

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Python and tools
sudo apt install -y python3 python3-pip python3-venv nginx nmap

# Install certbot for SSL
sudo apt install -y certbot python3-certbot-nginx
```

#### 2. Setup Application

```bash
# Create app directory
sudo mkdir -p /opt/ase
cd /opt/ase

# Clone repository
sudo git clone https://github.com/yourusername/ase-security-platform.git .

# Create virtual environment
sudo python3 -m venv venv
sudo venv/bin/pip install -r requirements.txt

# Setup environment
sudo cp .env.example .env
sudo nano .env  # Edit with your values
```

#### 3. Create Systemd Service

Create `/etc/systemd/system/ase.service`:

```ini
[Unit]
Description=ASE Security Platform
After=network.target

[Service]
Type=simple
User=www-data
WorkingDirectory=/opt/ase
Environment="PATH=/opt/ase/venv/bin"
ExecStart=/opt/ase/venv/bin/streamlit run app.py --server.port=8501 --server.address=127.0.0.1
Restart=always

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable ase
sudo systemctl start ase
sudo systemctl status ase
```

#### 4. Configure Nginx

Create `/etc/nginx/sites-available/ase`:

```nginx
server {
    listen 80;
    server_name your-domain.com;

    location / {
        proxy_pass http://127.0.0.1:8501;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 86400;
    }
}
```

Enable site:
```bash
sudo ln -s /etc/nginx/sites-available/ase /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx
```

#### 5. Setup SSL

```bash
sudo certbot --nginx -d your-domain.com
```

#### 6. Firewall Configuration

```bash
sudo ufw allow 'Nginx Full'
sudo ufw enable
```

---

## Security Considerations

### Before Deployment

1. **Change Default Credentials**
   - Update `ADMIN_ACCESS_CODE` in `.env`
   - Use strong, random passwords

2. **Secure API Keys**
   - Never commit `.env` to Git
   - Use environment variables or secrets management
   - Rotate keys regularly

3. **Remove Hardcoded Secrets**
   - Ensure no API keys in code
   - Check with: `git grep -i "api.*key"`

4. **Update Dependencies**
   ```bash
   pip list --outdated
   pip install --upgrade -r requirements.txt
   ```

### Production Best Practices

1. **Enable HTTPS**
   - Always use SSL/TLS in production
   - Use Let's Encrypt for free certificates

2. **Rate Limiting**
   - Configure Nginx rate limiting
   - Implement application-level throttling

3. **Monitoring**
   - Setup logging aggregation
   - Monitor resource usage
   - Configure alerts

4. **Backups**
   - Regular database backups
   - Configuration backups
   - Disaster recovery plan

5. **Updates**
   - Keep system packages updated
   - Monitor security advisories
   - Test updates in staging first

### Nginx Rate Limiting Example

Add to Nginx config:
```nginx
limit_req_zone $binary_remote_addr zone=ase_limit:10m rate=10r/s;

server {
    # ... other config ...
    
    location / {
        limit_req zone=ase_limit burst=20 nodelay;
        # ... proxy config ...
    }
}
```

---

## Troubleshooting

### Application Won't Start

```bash
# Check logs
sudo journalctl -u ase -f

# Check Python errors
cd /opt/ase
venv/bin/python app.py
```

### Port Already in Use

```bash
# Find process using port 8501
sudo lsof -i :8501

# Kill process
sudo kill -9 <PID>
```

### Nginx Errors

```bash
# Check Nginx logs
sudo tail -f /var/log/nginx/error.log

# Test configuration
sudo nginx -t
```

### SSL Certificate Issues

```bash
# Renew certificate
sudo certbot renew

# Test renewal
sudo certbot renew --dry-run
```

---

## Performance Optimization

### Streamlit Configuration

Create `.streamlit/config.toml`:

```toml
[server]
maxUploadSize = 200
enableXsrfProtection = true
enableCORS = false

[browser]
gatherUsageStats = false

[theme]
base = "dark"
```

### Nginx Caching

Add to Nginx config:
```nginx
proxy_cache_path /var/cache/nginx levels=1:2 keys_zone=ase_cache:10m max_size=1g inactive=60m;

location /static {
    proxy_cache ase_cache;
    proxy_cache_valid 200 1h;
}
```

---

## Monitoring

### Setup Logging

```bash
# Create log directory
sudo mkdir -p /var/log/ase

# Update systemd service
StandardOutput=append:/var/log/ase/output.log
StandardError=append:/var/log/ase/error.log
```

### Health Checks

Create monitoring script `/opt/ase/healthcheck.sh`:

```bash
#!/bin/bash
response=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8501/_stcore/health)
if [ $response != "200" ]; then
    echo "ASE is down! Response: $response"
    sudo systemctl restart ase
fi
```

Add to crontab:
```bash
*/5 * * * * /opt/ase/healthcheck.sh
```

---

## Scaling

### Horizontal Scaling

For high traffic, use multiple instances behind a load balancer:

1. Deploy multiple instances
2. Setup Nginx load balancing:

```nginx
upstream ase_backend {
    least_conn;
    server 127.0.0.1:8501;
    server 127.0.0.1:8502;
    server 127.0.0.1:8503;
}

server {
    location / {
        proxy_pass http://ase_backend;
    }
}
```

### Database Considerations

For production with multiple instances:
- Use PostgreSQL/MySQL instead of JSON files
- Implement session sharing (Redis)
- Centralize audit logs

---

## Support

For deployment issues:
- Check [GitHub Issues](https://github.com/yourusername/ase-security-platform/issues)
- Review application logs
- Consult Streamlit documentation

---

**Last Updated**: December 2025
