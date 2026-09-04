from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse
from email.header import decode_header
import email
import uvicorn

app = FastAPI(title="Email Threat Analysis Engine")

def clean_header_text(text: str) -> str:
    if not text:
        return ""
    decoded_fragments = decode_header(text)
    header_parts = []
    for fragment, encoding in decoded_fragments:
        if isinstance(fragment, bytes):
            header_parts.append(fragment.decode(encoding or "utf-8", errors="ignore"))
        else:
            header_parts.append(str(fragment))
    return "".join(header_parts)

def analyze_threat(from_addr: str, reply_to: str, subject: str, body: str) -> dict:
    flags = []
    
    # Phishing / BEC Keyword Checks
    keywords = ["urgent", "verify account", "password reset", "wire transfer", "action required", "unauthorized login", "bank", "invoice"]
    found = [kw for kw in keywords if kw in subject.lower() or kw in body.lower()]
    if found:
        flags.append(f"Suspicious Phishing Keywords: {', '.join(found)}")

    # Domain Mismatch Check
    if reply_to and reply_to != from_addr:
        from_domain = from_addr.split("@")[-1].replace(">", "").strip() if "@" in from_addr else ""
        reply_domain = reply_to.split("@")[-1].replace(">", "").strip() if "@" in reply_to else ""
        if from_domain and reply_domain and from_domain != reply_domain:
            flags.append(f"Spoofing Risk: Domain mismatch ('@{from_domain}' vs '@{reply_domain}')")

    status = "🚨 HIGH THREAT DETECTED" if flags else "✔ SAFE / LOW RISK"
    return {"status": status, "flags": flags}

@app.get("/", response_class=HTMLResponse)
def home():
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Email Threat Analyzer</title>
        <style>
            body { font-family: Arial, sans-serif; background: #121212; color: #fff; margin: 40px; }
            .container { max-width: 600px; margin: auto; background: #1e1e1e; padding: 25px; border-radius: 8px; }
            input, textarea { width: 100%; padding: 10px; margin: 10px 0; background: #2b2b2b; color: #fff; border: 1px solid #444; border-radius: 4px; box-sizing: border-box; }
            button { width: 100%; padding: 12px; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; font-weight: bold; }
            button:hover { background: #0056b3; }
        </style>
    </head>
    <body>
        <div class="container">
            <h2>🛡️ Email Threat Analysis Engine</h2>
            <form action="/analyze" method="post">
                <label>From Header:</label>
                <input type="text" name="from_addr" placeholder="e.g. Security <security@paypal-support.com>" required>
                <label>Reply-To Header (Optional):</label>
                <input type="text" name="reply_to" placeholder="e.g. attacker@gmail.com">
                <label>Subject:</label>
                <input type="text" name="subject" placeholder="e.g. Urgent: Account Suspended" required>
                <label>Email Body:</label>
                <textarea name="body" rows="5" placeholder="Paste email content here..."></textarea>
                <button type="submit">Analyze Email Threat</button>
            </form>
        </div>
    </body>
    </html>
    """

@app.post("/analyze", response_class=HTMLResponse)
def analyze(from_addr: str = Form(...), reply_to: str = Form(""), subject: str = Form(...), body: str = Form("")):
    result = analyze_threat(from_addr, reply_to, subject, body)
    
    flags_html = "".join([f"<li>{f}</li>" for f in result["flags"]]) if result["flags"] else "<li>No malicious indicators found.</li>"
    color = "#ff4d4d" if result["flags"] else "#4dff88"

    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Analysis Result</title>
        <style>
            body {{ font-family: Arial, sans-serif; background: #121212; color: #fff; margin: 40px; }}
            .container {{ max-width: 600px; margin: auto; background: #1e1e1e; padding: 25px; border-radius: 8px; }}
            a {{ color: #007bff; text-decoration: none; display: inline-block; margin-top: 15px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h2>Threat Analysis Result</h2>
            <h3 style="color: {color};">{result['status']}</h3>
            <h4>Details:</h4>
            <ul>{flags_html}</ul>
            <a href="/">← Analyze Another Email</a>
        </div>
    </body>
    </html>
    """

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
