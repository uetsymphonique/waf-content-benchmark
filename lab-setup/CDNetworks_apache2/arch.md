Here is a comprehensive description of our current Web Application Firewall (WAF) testing lab architecture and setup. You can use this directly for your research documentation or project reports.

### **High-Level Architecture Overview**
The lab is designed using a **Cloud-Based Reverse Proxy** model. It isolates the application backend from direct internet exposure, forcing all incoming traffic to be inspected by a Cloud WAF. The backend is specifically engineered as a resilient "Echo Server" to validate whether malicious payloads successfully bypass the WAF.



**Traffic Flow:**
`Attacker/Client` $\rightarrow$ `DNS (Namecheap)` $\rightarrow$ `CDNetworks WAF` $\rightarrow$ `Apache2 (VHost)` $\rightarrow$ `Python Flask Backend`

---

### **Detailed Component Setup**

#### **1. DNS & Routing Management (Namecheap)**
* **Domain:** mydomain.web
* **Subdomain:** `waftest.mydomain.web`
* **Configuration:** The subdomain utilizes a `CNAME` record pointing to the CDNetworks Edge server address (e.g., `waftest.mydomain.web.wcdnga.com`). This ensures that DNS resolution directs users to the CDN rather than the origin server.

#### **2. Cloud Web Application Firewall (CDNetworks)**
* **Role:** The primary security perimeter and reverse proxy.
* **Configuration:** * **Origin Protocol:** HTTP (Port 80).
    * **Origin IP:** Configured with the static public IP of the VPS backend (`x.x.x.x`).

#### **3. Web Server & Gateway (Apache2)**
* **Role:** Acts as the entry point on the origin server and a local reverse proxy.
* **Isolation (Virtual Hosts):** Configured with Name-Based Virtual Hosting (`ServerName waftest.mydomain.web`). This isolates the WAF testing environment from other applications running on the same server (e.g., Nextcloud).
* **Proxy Configuration:** Uses `mod_proxy` to forward validated HTTP requests to the internal Python backend at `http://127.0.0.1:5000/`.
* **Logging:** Maintains isolated logs (`waf_test_access.log` and `waf_test_error.log`) to track traffic that successfully reaches the server.

#### **4. Application Backend (Python/Flask)**
* **Role:** A highly resilient "Echo Server" designed to safely process and log any incoming data.
* **Environment:** Runs inside a Python virtual environment (`venv`) and is managed as a background daemon using `systemd` (`waf-backend.service`). 
* **Payload Handling:** It is engineered to prevent backend crashes (Error 502) when receiving malformed or malicious payloads.
    * Parses valid and malformed JSON safely.
    * Catches binary payloads (e.g., shellcode) and encodes them in `Base64` to avoid `UnicodeDecodeError`.
* **Response:** Always returns a `200 OK` status with a structured JSON response containing the HTTP method, path, body type, and the exact payload received. This provides concrete evidence of a WAF bypass.