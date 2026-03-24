# Lab: ModSecurity WAF + Nginx + Grafana Loki

## Environment

- OS: Ubuntu 22.04
- Architecture:

```
Internet → Nginx 1.29.3 :80 (ModSecurity WAF) → Python Backend :8080
                                                        ↓
                                          Promtail → Loki :3100 → Grafana :3000
```

---

## Components

| Component | Install Method | Reason |
|---|---|---|
| **libmodsecurity 3.0.14** | Build from source | apt version 3.0.6, not compatible with CRS v4 |
| **Nginx 1.29.3** | Build from source | Need to build with ModSecurity-nginx connector |
| **ModSecurity-nginx connector v1.0.4** | Build from source | Not in apt Ubuntu 22/24 |
| **OWASP CRS v4** | git clone | - |
| **Grafana** | apt | Official repo |
| **Loki + Promtail** | Binary download | Lightweight, no need to build |
| **Python backend** | Script | Simple test |

---

## Step 1 — Install dependencies

```bash
sudo apt update && sudo apt install -y \
  build-essential git wget \
  libpcre3-dev libssl-dev zlib1g-dev \
  libxml2-dev libcurl4-openssl-dev \
  pkg-config libtool autoconf \
  libpcre2-dev libyajl-dev liblmdb-dev \
  libgeoip-dev libmaxminddb-dev \
  libfuzzy-dev ssdeep
```

---

## Step 2 — Build libmodsecurity 3.0.14 from source

```bash
cd /opt
sudo git clone --depth 1 -b v3/master \
  https://github.com/owasp-modsecurity/ModSecurity.git

cd ModSecurity
sudo git submodule init && sudo git submodule update
sudo ./build.sh
sudo ./configure
sudo make -j$(nproc)
sudo make install
# Install to: /usr/local/modsecurity/

# Register with ldconfig
echo "/usr/local/modsecurity/lib" | \
  sudo tee /etc/ld.so.conf.d/modsecurity.conf
sudo ldconfig
```

---

## Step 3 — Clone ModSecurity-nginx connector

```bash
cd /opt
sudo git clone https://github.com/owasp-modsecurity/ModSecurity-nginx.git
```

---

## Step 4 — Build Nginx 1.29.3 + module

```bash
NGINX_VER="1.29.3"
cd /opt

sudo wget http://nginx.org/download/nginx-${NGINX_VER}.tar.gz
sudo tar zxvf nginx-${NGINX_VER}.tar.gz
cd nginx-${NGINX_VER}

sudo ./configure \
  --prefix=/etc/nginx \
  --sbin-path=/usr/sbin/nginx \
  --modules-path=/usr/lib/nginx/modules \
  --conf-path=/etc/nginx/nginx.conf \
  --error-log-path=/var/log/nginx/error.log \
  --http-log-path=/var/log/nginx/access.log \
  --pid-path=/run/nginx.pid \
  --with-compat \
  --with-http_ssl_module \
  --with-http_v2_module \
  --with-http_realip_module \
  --with-http_stub_status_module \
  --add-dynamic-module=/opt/ModSecurity-nginx

sudo make -j$(nproc)
sudo make install
```

---

## Step 5 — Systemd service cho Nginx

```bash
sudo tee /etc/systemd/system/nginx.service > /dev/null <<'EOF'
[Unit]
Description=nginx - high performance web server
After=network.target

[Service]
Type=forking
PIDFile=/run/nginx.pid
ExecStartPre=/usr/sbin/nginx -t
ExecStart=/usr/sbin/nginx
ExecReload=/bin/kill -s HUP $MAINPID
ExecStop=/bin/kill -s QUIT $MAINPID
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable nginx
```

---

## Step 6 — Configure ModSecurity

```bash
# Load module
sudo sed -i '1s/^/load_module \/usr\/lib\/nginx\/modules\/ngx_http_modsecurity_module.so;\n/' \
  /etc/nginx/nginx.conf

# Copy sample config
sudo cp /opt/ModSecurity/modsecurity.conf-recommended /etc/nginx/modsecurity.conf
sudo cp /opt/ModSecurity/unicode.mapping /etc/nginx/unicode.mapping

# Create audit log
sudo touch /var/log/modsec_audit.log
sudo chown www-data:adm /var/log/modsec_audit.log
sudo chmod 640 /var/log/modsec_audit.log
```

Edit `/etc/nginx/modsecurity.conf`:
```nginx
SecRuleEngine DetectionOnly   # Change to On when ready to block
SecRequestBodyAccess On
SecRequestBodyLimit 10485760
SecResponseBodyAccess Off
SecAuditEngine RelevantOnly
SecAuditLog /var/log/modsec_audit.log
SecAuditLogFormat JSON
SecAuditLogParts ABIJDEFHZ
SecAuditLogType Serial
SecTmpDir /tmp/
SecDataDir /tmp/
```

---

## Step 7 — Install OWASP CRS v4

```bash
cd /etc/nginx
sudo git clone https://github.com/coreruleset/coreruleset modsecurity-crs
sudo cp modsecurity-crs/crs-setup.conf.example \
        modsecurity-crs/crs-setup.conf
```

Add Paranoia Level to `crs-setup.conf`:
```nginx
SecAction \
  "id:900000,\
   phase:1,\
   nolog,\
   pass,\
   t:none,\
   setvar:tx.blocking_paranoia_level=1,\
   setvar:tx.detection_paranoia_level=2"
```

---

## Step 8 — File include and exclusion

```bash
sudo tee /etc/nginx/modsecurity-includes.conf > /dev/null <<'EOF'
Include /etc/nginx/modsecurity.conf
Include /etc/nginx/modsecurity-crs/crs-setup.conf
Include /etc/nginx/modsecurity-crs/rules/*.conf
EOF

sudo touch /etc/nginx/modsec-exclusions.conf
```

---

## Step 9 — Remove old modules-enabled (from apt)

```bash
sudo rm -f /etc/nginx/modules-enabled/*.conf
sudo rm /etc/nginx/sites-enabled/default
```

---

## Step 10 — Virtual host config

`/etc/nginx/sites-available/myapp.conf`:
```nginx
server {
    listen 80;
    server_name _;

    modsecurity on;
    modsecurity_rules_file /etc/nginx/modsecurity-includes.conf;

    client_max_body_size 10m;

    add_header X-Frame-Options        "SAMEORIGIN"    always;
    add_header X-Content-Type-Options "nosniff"       always;
    add_header X-XSS-Protection       "1; mode=block" always;

    location / {
        proxy_pass         http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    access_log /var/log/nginx/myapp_access.log;
    error_log  /var/log/nginx/myapp_error.log warn;
}
```

```bash
sudo ln -s /etc/nginx/sites-available/myapp.conf /etc/nginx/sites-enabled/
sudo systemctl start nginx
```

---

## Step 11 — Python backend (test)

```bash
sudo tee /opt/simple-server.py > /dev/null <<'EOF'
from http.server import HTTPServer, BaseHTTPRequestHandler
import json, base64

class Handler(BaseHTTPRequestHandler):
    def _send(self, status, body, extra_headers=None):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods",
                         "GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD")
        self.send_header("Access-Control-Allow-Headers",
                         "Content-Type, Authorization")
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        if body is not None:
            self.wfile.write(json.dumps(body).encode())

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        if not length:
            return None, "empty"
        raw = self.rfile.read(length)
        ct = self.headers.get("Content-Type", "")
        if "application/json" in ct:
            try:
                return json.loads(raw.decode("utf-8")), "json"
            except Exception:
                return raw.decode("utf-8", errors="replace"), "json_malformed"
        if any(t in ct for t in ["text/", "application/xml",
                                  "application/x-www-form-urlencoded"]):
            try:
                return raw.decode("utf-8"), "text"
            except Exception:
                pass
        if "multipart/form-data" in ct:
            return {"size_bytes": length, "note": "multipart not decoded"}, "multipart"
        try:
            return raw.decode("utf-8"), "text"
        except UnicodeDecodeError:
            return base64.b64encode(raw).decode(), "binary_base64"

    def do_GET(self):
        self._send(200, {"status": "ok", "method": "GET", "path": self.path})

    def do_POST(self):
        body, body_type = self._read_body()
        self._send(200, {"status": "ok", "method": "POST",
                         "path": self.path, "body_type": body_type, "body": body})

    def do_PUT(self):
        body, body_type = self._read_body()
        self._send(200, {"status": "ok", "method": "PUT",
                         "path": self.path, "body_type": body_type, "body": body})

    def do_PATCH(self):
        body, body_type = self._read_body()
        self._send(200, {"status": "ok", "method": "PATCH",
                         "path": self.path, "body_type": body_type, "body": body})

    def do_DELETE(self):
        body, body_type = self._read_body()
        self._send(200, {"status": "ok", "method": "DELETE",
                         "path": self.path, "body_type": body_type, "body": body})

    def do_OPTIONS(self):
        self._send(204, None)

    def do_HEAD(self):
        self._send(200, None)

    def log_message(self, format, *args):
        print(f"[backend] {self.address_string()} - {format % args}")

if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", 8080), Handler)
    print("Backend running on http://0.0.0.0:8080")
    server.serve_forever()
EOF

sudo tee /etc/systemd/system/simple-backend.service > /dev/null <<'EOF'
[Unit]
Description=Simple Python Backend
After=network.target

[Service]
ExecStart=/usr/bin/python3 /opt/simple-server.py
Restart=always
User=www-data

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable simple-backend
sudo systemctl start simple-backend
```

---

## Step 12 — Install Grafana

```bash
sudo apt install -y apt-transport-https software-properties-common wget

wget -q -O - https://apt.grafana.com/gpg.key | \
  sudo gpg --dearmor -o /etc/apt/keyrings/grafana.gpg

echo "deb [signed-by=/etc/apt/keyrings/grafana.gpg] \
  https://apt.grafana.com stable main" | \
  sudo tee /etc/apt/sources.list.d/grafana.list

sudo apt update && sudo apt install -y grafana
sudo systemctl enable grafana-server
sudo systemctl start grafana-server
```

---

## Step 13 — Install Loki + Promtail

```bash
LOKI_VER=$(curl -s https://api.github.com/repos/grafana/loki/releases/latest \
  | grep tag_name | cut -d'"' -f4 | tr -d 'v')

cd /tmp
wget "https://github.com/grafana/loki/releases/download/v${LOKI_VER}/loki-linux-amd64.zip"
wget "https://github.com/grafana/loki/releases/download/v${LOKI_VER}/promtail-linux-amd64.zip"

unzip loki-linux-amd64.zip && sudo mv loki-linux-amd64 /usr/local/bin/loki
unzip promtail-linux-amd64.zip && sudo mv promtail-linux-amd64 /usr/local/bin/promtail
sudo chmod 755 /usr/local/bin/loki /usr/local/bin/promtail
```

`/etc/loki/config.yml`:
```yaml
auth_enabled: false
server:
  http_listen_port: 3100
  grpc_listen_port: 9096
  log_level: warn
common:
  path_prefix: /var/lib/loki
  storage:
    filesystem:
      chunks_directory: /var/lib/loki/chunks
      rules_directory: /var/lib/loki/rules
  replication_factor: 1
  ring:
    instance_addr: 127.0.0.1
    kvstore:
      store: inmemory
schema_config:
  configs:
    - from: 2024-01-01
      store: tsdb
      object_store: filesystem
      schema: v13
      index:
        prefix: index_
        period: 24h
limits_config:
  retention_period: 7d
  ingestion_rate_mb: 4
  ingestion_burst_size_mb: 8
compactor:
  working_directory: /var/lib/loki/compactor
  retention_enabled: true
  delete_request_store: filesystem
analytics:
  reporting_enabled: false
```

`/etc/promtail/config.yml`:
```yaml
server:
  http_listen_port: 9080
  grpc_listen_port: 0
  log_level: warn
positions:
  filename: /var/lib/promtail/positions.yaml
clients:
  - url: http://localhost:3100/loki/api/v1/push
scrape_configs:
  - job_name: modsecurity
    static_configs:
      - targets: [localhost]
        labels:
          job: modsecurity
          host: ubuntu
          __path__: /var/log/modsec_audit.log
  - job_name: nginx_access
    static_configs:
      - targets: [localhost]
        labels:
          job: nginx_access
          host: ubuntu
          __path__: /var/log/nginx/myapp_access.log
  - job_name: nginx_error
    static_configs:
      - targets: [localhost]
        labels:
          job: nginx_error
          host: ubuntu
          __path__: /var/log/nginx/myapp_error.log
```

```bash
sudo systemctl enable loki promtail
sudo systemctl start loki promtail
```

---

## Permissions

```bash
sudo chown www-data:adm /var/log/nginx/myapp_access.log
sudo chown www-data:adm /var/log/nginx/myapp_error.log
sudo chown www-data:adm /var/log/modsec_audit.log
sudo chmod 640 /var/log/nginx/myapp_access.log \
               /var/log/nginx/myapp_error.log \
               /var/log/modsec_audit.log
sudo chmod 644 /usr/lib/nginx/modules/ngx_http_modsecurity_module.so
```

---

## Verify

```bash
echo "=== Nginx ===" && curl -sI http://localhost | grep Server
echo "=== Services ===" && systemctl is-active nginx simple-backend loki promtail grafana-server
echo "=== libmodsecurity ===" && grep "libmodsecurity3 version" /var/log/nginx/error.log | tail -1
echo "=== CRS rules ===" && grep "rules loaded" /var/log/nginx/error.log | tail -1
echo "=== Backend ===" && curl -s http://localhost/api/test
echo "=== WAF detect ===" && curl -s "http://localhost/?id=1%27%20OR%20%271%27%3D%271" | head -1
echo "=== Loki ===" && curl -s http://localhost:3100/ready
echo "=== Grafana ===" && curl -s -o /dev/null -w "%{http_code}" http://localhost:3000
```

---

## Enable blocking mode (when ready)

```bash
sudo sed -i 's/SecRuleEngine DetectionOnly/SecRuleEngine On/' \
  /etc/nginx/modsecurity.conf
sudo systemctl restart nginx

# Test block
curl -s -o /dev/null -w "%{http_code}" \
  "http://localhost/?id=1%27%20OR%20%271%27%3D%271"
# Expected: 403
```
