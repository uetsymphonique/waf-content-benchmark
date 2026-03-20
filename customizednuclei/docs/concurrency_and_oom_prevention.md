# Concurrency & Memory Optimization Architecture

This document describes the design decisions made to transform the standard Nuclei vulnerability scanner into a highly concurrent and extremely memory-efficient WAF (Web Application Firewall) fuzzing tool.

---

## 1. Concurrency Model: The Worker Pool

Running thousands of Nuclei templates sequentially is slow. However, sharing a single Nuclei execution engine across multiple threads natively leads to unstable state cross-contamination.

To solve this, the CLI implements a **Worker Pool Architecture**:

1. **Job Distribution**: Upon start, the `main` thread discovers all target YAML template paths and stores them. It pushes these file paths (strings) into a buffered Go channel (`jobs`).
2. **Isolated Workers**: The engine spins up `N` concurrent goroutines (controlled by the `-c` flag). 
3. **Independent Engine Instantiation**: Crucially, **each worker initializes and owns its own independent `runner.Runner` and Nuclei Engine**. 
   - This ensures that heavy SDK data operations inside Nuclei components do not overlap or race each other. 
   - Because engine initialization is extremely fast, this setup achieves massive logical separation for almost zero overhead.
4. **Thread-Safe I/O**: As each worker finishes fuzzing a template, it briefly locks a shared Mutex (`sync.Mutex`), writes exactly ONE aggregated row to the shared CSV file, updates the global statistics counters, and then immediately releases the lock to grab the next job.

---

## 2. OOM (Out-of-Memory) Prevention Setup

### The Original Memory Leak
In its native state, Nuclei logs "matches" (detected vulnerabilities) by generating heavy `ResultEvent` tracking objects. If a template outputs a match, the Engine wraps the HTTP request, header, body data, and metadata into this object and aggressively appends it to a slice inside `scan_context` in RAM.

When fuzzing WAFs, we rely on a `catch-all` mechanism so that *every single request* run by the fuzzer is captured to determine if the WAF bypassed it or blocked it.
Because thousands or millions of fuzz payloads were being logged as successful "matches", Nuclei accumulated millions of heavy `ResultEvent` structs in RAM simultaneously, causing immediate Out-of-Memory (OOM) crashes.

### The Fix: `false` Matcher + Streaming Callbacks
To completely eliminate memory scaling while maintaining 100% monitoring accuracy, we introduced a Two-Part Optimization:

#### A. The Semantic Exploit (`dsl: ["false"]`)
During the `preprocess` parsing phase, the engine strips out all original matchers and injects a single catch-all matcher that always evaluates to **`false`**.
```yaml
matchers:
  - type: dsl
    dsl:
      - "false"
```
Because the engine now officially registers **0 matches**, it automatically bypasses the payload accumulation phase. Memory allocation for `scan_context` remains completely flat (approx. 0MB overhead per template run).

#### B. Streaming `OnResult` Hooking
Since Nuclei isn't accumulating the data for us, we must track it manually without storing raw text data:
- We invoke the template via `ExecuteWithResults(scanCtx)` instead of blindly executing it.
- We hook the `scanCtx.OnResult` callback. Even though the template evaluated the matcher as `false`, this hook still intercepts the low-level HTTP interaction event before it is garbage collected.
- Inside the hook, we extract only the **HTTP Status Code** (e.g. 200, 403, 501) and increment a map structure: `map[int]int`.

### Outcome
This architectural combination guarantees $O(c)$ constant memory usage. Tracking 1 payload or 100 million payloads consumes the exact same amount of RAM, while allowing thousands of concurrent requests to fire efficiently.
