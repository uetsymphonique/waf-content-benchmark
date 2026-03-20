# WAF Benchmark — Implementation Notes

---

## 1. Template Preprocessing Pipeline

Thực hiện theo đúng thứ tự trước khi feed vào Nuclei engine:

1. **Skip interactsh sớm** — scan raw YAML string, nếu chứa `interactsh-url`, `{{interactsh`, hoặc `oast-` thì skip ngay, không parse. Cũng check lỗi trả về từ `templates.Parse()` nếu có chứa các từ khoá này.

2. **Xoá key `flow`** — Nuclei Flow dùng JS VM để chạy request có điều kiện; xoá để đảm bảo mọi HTTP request đều chạy tuần tự, không conditional.

3. **Set `stop-at-first-match: false`** — set ở cả root template level lẫn từng HTTP request object.

4. **Xoá matchers gốc** — xoá `matchers` và `matchers-condition` khỏi từng HTTP request.

5. **Inject catch-all matcher** — thay bằng `dsl: ["true"]` (name: `force-log`). Nuclei chỉ sinh `ResultEvent` khi có matcher match; catch-all này đảm bảo mọi request đều sinh result để đếm bypass/block.

6. **Resolve payload paths** — trong block `variables`, các value kết thúc `.txt` hoặc chứa `/payloads/` là relative path đến wordlist; resolve thành absolute dựa vào thư mục chứa template.

7. **Split payload file lớn** — nếu `.txt` vượt ngưỡng (cũ: 1500 dòng), chia thành N temp files tại `os.TempDir()`. Mỗi chunk → một bản copy modified template → một lần execute riêng. Chỉ split **một** variables entry (entry đầu tiên tìm thấy); các variables khác chỉ resolve path.

8. **Flatten payload arrays** — trong `payloads` block của request, Nuclei yêu cầu file path phải là `string` thuần. YAML thường parse ra `[]interface{}` (single-item array). Nếu item là variable reference thì tra `varMapCache` rồi assign string path; nếu là path trực tiếp thì resolve rồi assign. Ép kiểu `string(...)` rõ ràng — bắt buộc để trigger đúng `case string` trong `load.go` của Nuclei.

9. **Temp file cho modified template** — tạo tại `os.TempDir()` (không tạo cùng folder với template). Reset `template.Path` về path gốc sau khi parse. Xoá temp file ngay sau khi execute xong chunk.

---

## 2. Execution Flow per Template

- Wrap toàn bộ execution trong `defer recover()` — một template panic không crash cả run, ghi `failed` và tiếp tục.
- `defer MarkCompleted(templatePath)` để đảm bảo template luôn được đánh dấu xong dù có lỗi.
- Sau `preprocessTemplate()` thu được 1..N chunks; mỗi chunk chạy `templates.Parse()` + `ExecuteWithResults()` riêng.
- Kết quả từ `ExecuteWithResults()` và `scanCtx.OnResult` callback được merge và deduplicate theo key `templateID|matched|timestamp`.
- Nếu kết quả sau dedup vẫn là 0: tạo **synthetic result** với `status_code=403` và `synthetic_result=true` để đảm bảo mọi template đều có ít nhất một row trong CSV.
- Sau tất cả chunks: gọi `FinalizeTemplate()`, nếu fully bypassed thì ghi thêm một row vào file bypassed-templates summary.

---

## 3. Bypass Detection

**Prerequisite:** Tool phụ thuộc vào header `X-WAF-Status` được inject bởi test harness bên ngoài (reverse proxy giữa tool và WAF). Không có header này thì `strict` và `header` mode không bao giờ detect bypass.

**3 modes:**

| Mode | Điều kiện bypass |
|---|---|
| `strict` (default) | HTTP 200 AND `X-WAF-Status: Passed` |
| `header` | Chỉ `X-WAF-Status: Passed` |
| `status-only` | Chỉ HTTP 200 |

**Status code extraction** (theo priority):
1. `internalEvent["status_code"]` — int hoặc float64
2. Parse dòng đầu của `result.Response` (`HTTP/1.1 NNN ...`)
3. Fallback: 0

**WAF header extraction** (theo priority) — Nuclei normalize header: `X-WAF-Status` → `x_waf_status`:
1. `internalEvent["x_waf_status"]`
2. `result.Metadata["x_waf_status"]`
3. `result.Metadata["waf_status"]`
4. `result.Metadata["response_headers"]` as `http.Header`
5. Scan toàn bộ metadata keys case-insensitively

---

## 4. Two-Level Bypass Statistics

**Request-level:** mỗi `ResultEvent` = một HTTP request. Đếm global bypassed/blocked count và per-template counters.

**Template-level:** sau khi tất cả chunks xong, `FinalizeTemplate()` phân loại:
- **Fully bypassed** — tất cả requests đều bypassed (`blocked == 0`)
- **Blocked** — có ít nhất một request bị block

Template bypass rate khắt khe hơn request bypass rate và có ý nghĩa hơn.

---

## 5. State Management

State lưu vào JSON file để hỗ trợ resume. Các trường chính:
- `completed_templates` — danh sách full file path đã xong (dùng để GetNextBatch)
- `bypassed_count` / `blocked_count` — request-level counters
- `bypassed_templates` / `blocked_templates` — map templateID → bool (template-level)
- `template_requests` — map templateID → `{total, bypassed, blocked}`
- `skipped_templates` — map templateID → lý do (vd: "requires interactsh")
- `failed_templates` — map templateID → error message

`GetNextBatch` build set từ `completed_templates` rồi filter toàn bộ allTemplates, trả về N path chưa chạy. Key so sánh là **full file path**, không phải template ID.

---

## 6. CSV Output — 3 Files

| File | Nội dung |
|---|---|
| `results.csv` | Mọi request (bypassed + blocked) |
| `results_bypassed.csv` | Chỉ bypassed requests |
| `results_bypassed_templates.csv` | 1 row mỗi template fully bypassed |

Tên file 2 và 3 được auto-generate từ tên file 1 nếu không chỉ định.

**Columns** (file 1 & 2): Template ID, Template Name, Severity, Target URL, Status, HTTP Status Code, X-WAF-Status Header, Timestamp, Payload, Flow Index, Total Flow.

**Columns** (file 3): Template ID, Template Name, Severity, Total Requests.

Dùng `sync.Mutex` cho mọi write operation. Gọi `file.Sync()` sau mỗi chunk để đảm bảo data xuống disk khi crash.

---

## 7. Nuclei Setup — Những điểm bắt buộc

- `StoreResponse: true` — không có thì không extract được status code từ `result.Response`
- `AllowLocalFileAccess: true` — không có thì không load được `.txt` payload files
- `parser.ShouldValidate = false` và `parser.NoStrictSyntax = true` — cho phép parse template không hoàn chỉnh
- `protocolinit.Init()` phải gọi **một lần** trước khi tạo `ExecutorOptions`
- `Output` và `Progress` trong `ExecutorOptions` phải là non-nil (dùng VoidWriter/VoidProgress); để nil sẽ panic bên trong engine

---

## 8. Known Issues cần fix khi implement

- CSV headers bị duplicate 2 cột ("WAF Status Header", "Timestamp") — fix thành 11 columns đúng
- Chunk size 1500 đang hardcoded — nên là named constant hoặc configurable
- Chỉ split một payload variable per template — nếu template có nhiều large variables thì chỉ split cái đầu tiên
