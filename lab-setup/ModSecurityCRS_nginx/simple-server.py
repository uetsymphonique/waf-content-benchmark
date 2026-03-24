from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import base64

class Handler(BaseHTTPRequestHandler):

    def _send(self, status, body, extra_headers=None):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
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
        content_type = self.headers.get("Content-Type", "")

        # JSON
        if "application/json" in content_type:
            try:
                return json.loads(raw.decode("utf-8")), "json"
            except Exception:
                return raw.decode("utf-8", errors="replace"), "json_malformed"

        # Text
        if any(t in content_type for t in ["text/", "application/xml",
                                             "application/x-www-form-urlencoded"]):
            try:
                return raw.decode("utf-8"), "text"
            except Exception:
                pass

        if "multipart/form-data" in content_type:
            return {"size_bytes": length, "note": "multipart not decoded"}, "multipart"

        try:
            raw.decode("utf-8")
            return raw.decode("utf-8"), "text"
        except UnicodeDecodeError:
            return base64.b64encode(raw).decode(), "binary_base64"

    def do_GET(self):
        self._send(200, {"status": "ok", "method": "GET", "path": self.path})

    def do_POST(self):
        body, body_type = self._read_body()
        self._send(200, {
            "status": "ok", "method": "POST",
            "path": self.path,
            "body_type": body_type,
            "body": body
        })

    def do_PUT(self):
        body, body_type = self._read_body()
        self._send(200, {
            "status": "ok", "method": "PUT",
            "path": self.path,
            "body_type": body_type,
            "body": body
        })

    def do_PATCH(self):
        body, body_type = self._read_body()
        self._send(200, {
            "status": "ok", "method": "PATCH",
            "path": self.path,
            "body_type": body_type,
            "body": body
        })

    def do_DELETE(self):
        body, body_type = self._read_body()
        self._send(200, {
            "status": "ok", "method": "DELETE",
            "path": self.path,
            "body_type": body_type,
            "body": body
        })

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