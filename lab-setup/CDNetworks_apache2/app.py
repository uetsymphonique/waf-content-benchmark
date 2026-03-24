from flask import Flask, request, jsonify
import base64
import json
from werkzeug.routing import BaseConverter

app = Flask(__name__)

# Disable automatic semicolon path parameter stripping
class EverythingConverter(BaseConverter):
    regex = '.*?'

app.url_map.converters['everything'] = EverythingConverter

def parse_body():
    if request.content_length in (None, 0):
        return None, "empty"
    

    raw = request.get_data()
    content_type = request.content_type or ""


    if "application/json" in content_type:
        try:
            return json.loads(raw.decode('utf-8')), "json"
        except Exception:
            return raw.decode('utf-8', errors="replace"), "json_malformed"
    

    if any(t in content_type for t in ["text/", "application/xml", "application/x-www-form-urlencoded"]):
        return raw.decode('utf-8', errors="replace"), "text"

    if "multipart/form-data" in content_type:
        return {"size_bytes": request.content_length, "note": "multipart not decoded"}, "multipart"

    try:
        return raw.decode('utf-8'), "text"
    except UnicodeDecodeError:
        
        return base64.b64encode(raw).decode('utf-8'), "binary_base64"

@app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD'])
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD'])
def catch_all(path):
    if request.method == 'OPTIONS':
        return "", 204

    # Use full_path to capture semicolons and query strings that Flask routing strips
    full_path = request.full_path.rstrip('?')  # Remove trailing '?' if no query string
    
    body, body_type = parse_body()

    response_data = {
        "status": "ok",
        "method": request.method,
        "path": full_path,
        "body_type": body_type,
        "body": body
    }

    print(f"\n[+] {request.method} {full_path} | Type: {body_type}", flush=True)
    if body:
        print(f"Payload: {body}", flush=True)

    return jsonify(response_data), 200


@app.after_request
def add_cors_headers(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
    return response

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000)