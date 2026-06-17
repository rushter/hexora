#!/usr/bin/env python3
import http.server
import json
import os
import sys
import zipfile
import tarfile
import base64
import io
import urllib.parse

PACKAGES_DIR = None
DATASET_FILE = "dataset.jsonl"


def load_dataset():
    if not os.path.exists(DATASET_FILE):
        return []
    entries = []
    with open(DATASET_FILE, "r") as f:
        for line in f:
            line = line.strip()
            if line:
                entries.append(json.loads(line))
    return entries


def append_to_dataset(entry):
    with open(DATASET_FILE, "a") as f:
        f.write(json.dumps(entry, separators=(",", ":")) + "\n")


def list_archives():
    archives = []
    for fname in sorted(os.listdir(PACKAGES_DIR)):
        if fname.endswith(".zip") or fname.endswith(".tar.gz") or fname.endswith(".tgz"):
            archives.append(fname)
    return archives


def get_unreviewed_archives():
    dataset = load_dataset()
    reviewed = {entry["archive"] for entry in dataset}
    all_archives = list_archives()
    return [a for a in all_archives if a not in reviewed]


def extract_py_files(archive_name):
    path = os.path.join(PACKAGES_DIR, archive_name)
    files = []

    if archive_name.endswith(".zip"):
        z = zipfile.ZipFile(path)
        try:
            first = next((n for n in z.namelist() if not n.endswith("/") and n.endswith(".py")), None)
            if first:
                z.read(first)
        except RuntimeError:
            z.close()
            z = zipfile.ZipFile(path)
            z.setpassword(b"infected")
        for name in z.namelist():
            if not name.endswith(".py"):
                continue
            info = z.getinfo(name)
            content = z.read(name)
            files.append({
                "name": name,
                "content": base64.b64encode(content).decode("ascii"),
                "size": info.file_size,
            })
        z.close()
    elif archive_name.endswith(".tar.gz") or archive_name.endswith(".tgz"):
        with tarfile.open(path, "r:gz") as tar:
            for m in tar.getmembers():
                if not m.name.endswith(".py") or not m.isfile():
                    continue
                f = tar.extractfile(m)
                if f is None:
                    continue
                content = f.read()
                files.append({
                    "name": m.name,
                    "content": base64.b64encode(content).decode("ascii"),
                    "size": m.size,
                })
    return files


HTML_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Malware Labeler</title>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@picocss/pico@2/css/pico.min.css">
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/styles/default.min.css">
  <script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/highlight.min.js"></script>
  <style>
    .file-card { margin-bottom: 1rem; }
    .file-header { display: flex; justify-content: space-between; align-items: center; }
    .nav-bar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem; }
    .modal-overlay {
      position: fixed; inset: 0; background: rgba(0,0,0,0.5);
      display: flex; align-items: center; justify-content: center; z-index: 100;
    }
    .modal { background: var(--card-background-color, #fff); padding: 2rem; border-radius: 8px; min-width: 400px; }
    .modal textarea { width: 100%; min-height: 80px; }
    .actions { display: flex; gap: 0.5rem; }
    #status { margin-bottom: 1rem; }
    .binary-notice { font-style: italic; color: var(--muted-color); }
    .code-block { font-family: monospace; font-size: .875rem; line-height: 1.5; max-height: 600px; overflow: auto; border: 1px solid var(--muted-border-color); border-radius: 4px; margin: 0.5rem 0; }
    .code-line { display: flex; min-height: 1.5em; cursor: pointer; }
    .code-line:hover { background: var(--primary-hover-background, rgba(128,128,128,0.1)); }
    .code-line.selected { background: var(--del-color, rgba(255,0,0,0.15)); }
    .line-num { flex-shrink: 0; width: 4ch; text-align: right; padding: 0 1ch 0 0; color: var(--muted-color); user-select: none; border-right: 1px solid var(--muted-border-color); margin-right: 1ch; }
    .line-code { flex: 1; white-space: pre; }
  </style>
</head>
<body>
  <main class="container" style="padding-top: 2rem;">
    <h1>Malware Labeler</h1>
    <div id="status"></div>
    <div class="nav-bar">
      <button id="prevBtn" class="outline">← Prev</button>
      <span id="progress"></span>
      <button id="nextBtn" class="outline">Next →</button>
    </div>
    <div id="packageView"></div>
  </main>

  <div id="modalOverlay" class="modal-overlay" style="display:none;">
    <div class="modal">
      <h3 id="modalTitle">Flag as malicious</h3>
      <p id="modalFile"></p>
      <textarea id="modalReason" placeholder="Enter reason..."></textarea>
      <div class="actions" style="margin-top: 1rem;">
        <button id="modalCancel" class="outline">Cancel</button>
        <button id="modalConfirm" class="contrast">Submit</button>
      </div>
    </div>
  </div>

  <script>
    let archives = [];
    let currentIndex = 0;
    let currentFiles = [];
    let modalMode = null;
    let modalFile = null;
    let modalLines = null;
    const selectedLines = new Map();

    function clearSelectedLines() {
      selectedLines.clear();
    }

    function getFileSelectedLines(fileName) {
      return selectedLines.get(fileName);
    }

    function toggleLine(fileName, lineno) {
      if (!selectedLines.has(fileName)) {
        selectedLines.set(fileName, new Set());
      }
      const s = selectedLines.get(fileName);
      if (s.has(lineno)) { s.delete(lineno); } else { s.add(lineno); }
    }

    function getFlagButtonLabel(fileName) {
      const s = selectedLines.get(fileName);
      if (s && s.size > 0) {
        return `Flag selected (${s.size} line${s.size > 1 ? 's' : ''})`;
      }
      return 'Flag whole file';
    }

    async function loadArchives() {
      const r = await fetch('/api/packages');
      archives = await r.json();
      if (archives.length === 0) {
        document.getElementById('packageView').innerHTML = '<article><strong>All packages reviewed.</strong></article>';
        document.getElementById('progress').textContent = 'Done';
        return;
      }
      currentIndex = 0;
      showCurrent();
    }

    async function showCurrent() {
      clearSelectedLines();
      const pkg = archives[currentIndex];
      document.getElementById('progress').textContent = `${currentIndex + 1} / ${archives.length}`;
      document.getElementById('prevBtn').disabled = currentIndex === 0;
      document.getElementById('nextBtn').disabled = currentIndex === archives.length - 1;
      const r = await fetch(`/api/files?archive=${encodeURIComponent(pkg)}`);
      const data = await r.json();
      currentFiles = data.files || [];
      renderPackage(pkg, currentFiles);
    }

    function renderCodeWithLines(content, fileName) {
      const raw = hljs.highlight(content, {language: 'python'}).value;
      const lines = raw.split('\\n');
      const s = selectedLines.get(fileName);
      let html = '<div class="code-block">';
      for (let i = 0; i < lines.length; i++) {
        const lineno = i + 1;
        const sel = s && s.has(lineno) ? ' selected' : '';
        const code = lines[i] || ' ';
        html += `<div class="code-line${sel}" data-lineno="${lineno}">`;
        html += `<span class="line-num">${lineno}</span>`;
        html += `<span class="line-code">${code}</span>`;
        html += `</div>`;
      }
      html += '</div>';
      return html;
    }

    function renderPackage(pkg, files) {
      const view = document.getElementById('packageView');
      let html = `<article><header><strong>${htmlEscape(pkg)}</strong> <span class="badge">${files.length} .py files</span></header>`;

      for (const f of files) {
        let contentHtml = '';
        if (f.binary) {
          contentHtml = `<p class="binary-notice">[Binary file, ${f.size} bytes — not valid UTF-8]</p>`;
        } else {
          const decoded = atob(f.content);
          contentHtml = renderCodeWithLines(decoded, f.name);
        }
        const label = getFlagButtonLabel(f.name);
        html += `
          <div class="file-card" data-file="${htmlEscape(f.name)}">
            <div class="file-header">
              <strong>${htmlEscape(f.name)}</strong>
              <button class="outline contrast malicious-btn">${label}</button>
            </div>
            ${contentHtml}
          </div>
          <hr>
        `;
      }

      if (files.length === 0) {
        html += `<p>No .py files found in this archive.</p>`;
      }

      html += `
        <footer style="display: flex; justify-content: space-between;">
          <button class="outline secondary" id="skipBtn">Skip</button>
          <button class="contrast" id="benignBtn">Flag as benign</button>
        </footer>
      </article>`;
      view.innerHTML = html;
    }

    function htmlEscape(s) {
      return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
    }

    function openMaliciousModal(fileName, lines) {
      modalMode = 'malicious';
      modalFile = fileName;
      modalLines = lines;
      document.getElementById('modalTitle').textContent = 'Flag as malicious';
      const info = lines ? `File: ${fileName} — Lines: ${lines.join(', ')}` : `File: ${fileName} — Entire file`;
      document.getElementById('modalFile').textContent = info;
      document.getElementById('modalReason').value = '';
      document.getElementById('modalOverlay').style.display = 'flex';
    }

    function openBenignModal() {
      modalMode = 'benign';
      modalFile = null;
      modalLines = null;
      document.getElementById('modalTitle').textContent = 'Flag as benign';
      document.getElementById('modalFile').textContent = `Package: ${archives[currentIndex]}`;
      document.getElementById('modalReason').value = '';
      document.getElementById('modalOverlay').style.display = 'flex';
    }

    document.getElementById('modalCancel').onclick = function() {
      document.getElementById('modalOverlay').style.display = 'none';
    };

    document.getElementById('modalConfirm').onclick = async function() {
      const reason = document.getElementById('modalReason').value.trim();
      if (!reason) {
        alert('Please enter a reason / note.');
        return;
      }
      const archive = archives[currentIndex];
      const payload = {
        archive: archive,
        verdict: modalMode,
        reason: reason,
        lines: modalLines || null,
      };
      if (modalMode === 'malicious') {
        payload.file = modalFile;
        const f = currentFiles.find(x => x.name === modalFile);
        if (f) { payload.code = f.content; }
      }
      const r = await fetch('/api/flag', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(payload),
      });
      const result = await r.json();
      if (result.ok) {
        document.getElementById('modalOverlay').style.display = 'none';
        archives.splice(currentIndex, 1);
        if (archives.length === 0) {
          document.getElementById('packageView').innerHTML = '<article><strong>All packages reviewed.</strong></article>';
          document.getElementById('progress').textContent = 'Done';
          document.getElementById('prevBtn').disabled = true;
          document.getElementById('nextBtn').disabled = true;
        } else if (currentIndex >= archives.length) {
          currentIndex = archives.length - 1;
          showCurrent();
        } else {
          showCurrent();
        }
      } else {
        alert('Error: ' + (result.error || 'Unknown error'));
      }
    };

    function skipPackage() {
      archives.splice(currentIndex, 1);
      if (archives.length === 0) {
        document.getElementById('packageView').innerHTML = '<article><strong>All packages reviewed.</strong></article>';
        document.getElementById('progress').textContent = 'Done';
        document.getElementById('prevBtn').disabled = true;
        document.getElementById('nextBtn').disabled = true;
      } else if (currentIndex >= archives.length) {
        currentIndex = archives.length - 1;
        showCurrent();
      } else {
        showCurrent();
      }
    }

    document.getElementById('prevBtn').onclick = function() {
      if (currentIndex > 0) { currentIndex--; showCurrent(); }
    };
    document.getElementById('nextBtn').onclick = function() {
      if (currentIndex < archives.length - 1) { currentIndex++; showCurrent(); }
    };

    document.addEventListener('click', function(e) {
      if (e.target.id === 'skipBtn') { skipPackage(); }
      else if (e.target.id === 'benignBtn') { openBenignModal(); }
      else if (e.target.classList.contains('malicious-btn')) {
        const card = e.target.closest('.file-card');
        if (!card) return;
        const fileName = card.dataset.file;
        const s = selectedLines.get(fileName);
        const lines = s && s.size > 0 ? Array.from(s).sort((a,b) => a-b) : null;
        openMaliciousModal(fileName, lines);
      }
      else if (e.target.closest('.code-line')) {
        const line = e.target.closest('.code-line');
        const card = line.closest('.file-card');
        if (!card) return;
        const fileName = card.dataset.file;
        const lineno = parseInt(line.dataset.lineno);
        toggleLine(fileName, lineno);
        line.classList.toggle('selected');
        const btn = card.querySelector('.malicious-btn');
        if (btn) btn.textContent = getFlagButtonLabel(fileName);
      }
      else if (e.target === document.getElementById('modalOverlay')) {
        document.getElementById('modalOverlay').style.display = 'none';
      }
    });

    loadArchives();
  </script>
</body>
</html>
"""


class LabelerHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)

        if parsed.path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(HTML_PAGE.encode("utf-8"))

        elif parsed.path == "/api/packages":
            unreviewed = get_unreviewed_archives()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(unreviewed).encode("utf-8"))

        elif parsed.path == "/api/files":
            archive = params.get("archive", [None])[0]
            if not archive:
                self.send_response(400)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": "Missing archive param"}).encode("utf-8"))
                return
            try:
                files = extract_py_files(archive)
                for f in files:
                    try:
                        base64.b64decode(f["content"]).decode("utf-8")
                    except (UnicodeDecodeError, ValueError):
                        f["binary"] = True
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"files": files}).encode("utf-8"))
            except Exception as e:
                self.send_response(500)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": str(e), "files": []}).encode("utf-8"))

        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        content_len = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_len)
        parsed = urllib.parse.urlparse(self.path)

        if parsed.path == "/api/flag":
            try:
                data = json.loads(body)
            except json.JSONDecodeError:
                self.send_response(400)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": "Invalid JSON"}).encode("utf-8"))
                return

            archive = data.get("archive", "")
            verdict = data.get("verdict", "")
            file_name = data.get("file", "")
            reason = data.get("reason", "")
            code_b64 = data.get("code", "")
            lines = data.get("lines")

            if not archive or not verdict:
                self.send_response(400)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": "Missing archive or verdict"}).encode("utf-8"))
                return

            append_to_dataset({
                "archive": archive,
                "file": file_name,
                "reason": reason,
                "code": code_b64,
                "verdict": verdict,
                "lines": lines,
            })

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"ok": True}).encode("utf-8"))

        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        sys.stderr.write("[%s] %s\n" % (self.log_date_time_string(), format % args))


def main():
    global PACKAGES_DIR
    if len(sys.argv) < 2:
        print("Usage: python labeler.py <packages_directory>", file=sys.stderr)
        sys.exit(1)
    PACKAGES_DIR = sys.argv[1]
    if not os.path.isdir(PACKAGES_DIR):
        print(f"Error: {PACKAGES_DIR} is not a directory", file=sys.stderr)
        sys.exit(1)

    port = int(os.environ.get("PORT", 8000))
    server = http.server.HTTPServer(("0.0.0.0", port), LabelerHandler)
    print(f"Labeler running on http://0.0.0.0:{port}")
    print(f"Packages directory: {PACKAGES_DIR}")
    print(f"Dataset file: {os.path.abspath(DATASET_FILE)}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
        server.shutdown()


if __name__ == "__main__":
    main()
