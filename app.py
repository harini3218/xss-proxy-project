from flask import Flask, request, Response, jsonify, render_template
import requests
import re
import urllib.parse
import datetime
import os
import html

app = Flask(__name__)

TARGET = "http://127.0.0.1:3000"
LOG_FILE = "xss_log.txt"
PATTERN_FILE = "learned_patterns.txt"

SAFE_TAGS = ["h1", "h2", "h3", "p", "b", "i", "u"]

# =========================
# NORMALIZATION (NEW)
# =========================
def normalize_input(data):
    prev = ""
    while prev != data:
        prev = data
        data = urllib.parse.unquote(data)
    data = html.unescape(data)
    return data.lower()


# =========================
# XSS TYPE DETECTION
# =========================
def get_xss_type(source="unknown", location="unknown", data=""):
    location = location.lower()

    if any(x in location for x in ["search", "query", "#"]):
        return "DOM-Based XSS"

    if any(x in location for x in ["feedback", "comment", "review"]):
        return "Stored XSS"

    if "<" in data and ">" in data:
        return "Reflected XSS"

    return "Unknown XSS"


# =========================
# LOAD & SAVE PATTERNS
# =========================
def load_patterns():
    patterns = {}
    if os.path.exists(PATTERN_FILE):
        with open(PATTERN_FILE, "r") as f:
            for line in f:
                if ":" in line:
                    k, v = line.strip().split(":")
                    patterns[k] = int(v)
    return patterns


def save_patterns(patterns):
    with open(PATTERN_FILE, "w") as f:
        for k, v in patterns.items():
            f.write(f"{k}:{v}\n")


# =========================
# UPDATE LEARNING (FIXED)
# =========================
def update_pattern_count(tokens):
    patterns = load_patterns()
    for token in tokens:
        patterns[token] = patterns.get(token, 0) + 1
    save_patterns(patterns)


# =========================
# TOKEN EXTRACTION (IMPROVED)
# =========================
def extract_tokens(data):
    tokens = []

    tokens += re.findall(r"<\s*([a-z0-9]+)", data)
    tokens += re.findall(r"(on[a-z]+)\s*=", data)
    tokens += re.findall(r"(alert|confirm|prompt|eval)\s*\(", data)

    if "javascript:" in data:
        tokens.append("javascript:")

    # ❌ Remove safe tags
    tokens = [t for t in tokens if t not in SAFE_TAGS]

    return list(set(tokens))


# =========================
# STRONG XSS CHECK
# =========================
def is_strong_xss(data):
    patterns = [
        "<script", "</script", "alert(",
        "onerror=", "onload=", "javascript:",
        "<svg", "document.cookie"
    ]
    return any(p in data for p in patterns)


# =========================
# SCORING (IMPROVED)
# =========================
def classify_attack(data):
    patterns = load_patterns()
    score = 0

    # Weight system
    weights = {
        "script": 5,
        "onerror": 4,
        "onload": 4,
        "alert": 4,
        "javascript:": 5,
        "img": 2,
        "svg": 3
    }

    for token, count in patterns.items():
        if token in data:
            weight = weights.get(token, 1)
            score += count * weight   # ✅ SUM instead of max

    return score


# =========================
# LOGGING
# =========================
def log_attack(level, attack_type, data):
    time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a") as f:
        f.write(f"{level} | {attack_type} | {time} | {data}\n")


# =========================
# MAIN PROXY
# =========================
@app.route('/', defaults={'path': ''}, methods=["GET", "POST"])
@app.route('/<path:path>', methods=["GET", "POST"])
def proxy(path):

    url = f"{TARGET}/{path}"

    if request.method == "GET":
        data = request.query_string.decode()
    else:
        data = request.get_data(as_text=True)

    # 🔥 NEW NORMALIZATION
    data = normalize_input(data)

    # =========================
    # HIGH LEVEL DETECTION
    # =========================
    if is_strong_xss(data):
        attack_type = get_xss_type("request", path, data)
        log_attack("HIGH", attack_type, data)
        return f"{attack_type} Blocked", 403

    # =========================
    # SCORE BASED
    # =========================
    score = classify_attack(data)

    if score >= 20:
        attack_type = get_xss_type("request", path, data)
        log_attack("HIGH", attack_type, data)
        return "Attack Blocked", 403

    elif score >= 10:
        attack_type = get_xss_type("request", path, data)
        log_attack("MEDIUM", attack_type, data)
        return "Suspicious Activity", 403

    # =========================
    # LEARNING (ONLY STRONG)
    # =========================
    tokens = extract_tokens(data)

    if tokens and is_strong_xss(data):
        update_pattern_count(tokens)
        attack_type = get_xss_type("request", path, data)
        log_attack("LOW", attack_type, data)

    # =========================
    # FORWARD REQUEST
    # =========================
    resp = requests.request(
        method=request.method,
        url=url,
        headers={key: value for key, value in request.headers if key != 'Host'},
        data=request.get_data(),
        cookies=request.cookies,
        allow_redirects=False
    )

    return Response(resp.content, resp.status_code)


# =========================
# STATS API
# =========================
@app.route('/stats')
def stats():
    high = medium = low = 0

    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r") as f:
            for line in f:
                if line.startswith("HIGH"):
                    high += 1
                elif line.startswith("MEDIUM"):
                    medium += 1
                elif line.startswith("LOW"):
                    low += 1

    return jsonify({
        "high": high,
        "medium": medium,
        "low": low
    })


# =========================
# LOGS API
# =========================
@app.route('/logs')
def get_logs():
    logs = []

    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r") as f:
            lines = f.readlines()[-10:]

        for line in lines:
            parts = line.strip().split(" | ")
            if len(parts) == 4:
                logs.append({
                    "level": parts[0],
                    "type": parts[1],
                    "time": parts[2],
                    "data": parts[3]
                })

    return jsonify(logs[::-1])


# =========================
# DASHBOARD
# =========================
@app.route('/dashboard')
def dashboard():
    return render_template("dashboard.html")


# =========================
# RUN
# =========================
if __name__ == "__main__":
    app.run(port=8080, debug=True)