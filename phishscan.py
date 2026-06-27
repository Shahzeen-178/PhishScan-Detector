import re
import email
import quopri
import os
import math
import tkinter as ctk
from tkinter import filedialog as fd

# ─────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────

KNOWN_BRANDS = [
    "paypal","amazon","microsoft","google","apple","netflix","facebook",
    "instagram","twitter","linkedin","dropbox","adobe","ebay","dhl",
    "fedex","ups","bank","bankofamerica","citibank","chase","wellsfargo",
    "hsbc","hbl","meezan","easypaisa","jazzcash","telenor","ufone","zong"
]

TRUSTED_TLDS = [".edu",".gov",".ac.pk",".gov.pk",".org"]

SUSPICIOUS_TLDS = [".xyz",".tk",".top",".ml",".cf",".ga",".work",".loan",
                   ".click",".win",".gq",".zip",".review"]

SHORTENERS = ["bit.ly","tinyurl.com","t.co","goo.gl","ow.ly","is.gd",
              "buff.ly","adf.ly","shorte.st","bc.vc"]

PHISHING_TOOLS = ["gophish","zphisher","evilginx","social-engineer",
                  "set toolkit","hiddeneye","blackeye","modlishka","king-phisher"]

# 3-tier keywords: (word, tier)
KEYWORDS = []  # loaded from keywords.txt
DEFAULT_KEYWORDS = """# PhishScan Keywords - edit freely (tier1=3pts, tier2=2pts, tier3=1pt)
# FORMAT: word,tier
verify,1
suspended,1
account locked,1
unusual activity,1
immediate action,1
confirm your identity,1
update your payment,1
your account will be closed,1
security alert,1
unauthorized access,1
click here to verify,1
login attempt,1
wire transfer,2
bank details,2
credit card,2
social security,2
password expired,2
urgent,2
act now,2
limited time,2
congratulations you won,2
claim your prize,2
dear customer,3
verify,3
update,3
account,3
password,3
confirm,3
notification,3
"""

PHISHING_CORPUS = [
    "click here verify your account immediately suspended unauthorized",
    "confirm your identity bank details credit card wire transfer urgent",
    "dear customer your account will be suspended act now limited time offer",
    "congratulations you have won claim your prize click the link below",
    "security alert unusual login attempt verify password immediately",
    "your paypal account has been limited please verify your information",
    "amazon order confirm payment update billing information now",
    "microsoft account suspended verify email immediately security breach",
    "urgent action required account closure bank statement update",
]

SAFE_CORPUS = [
    "your order has been shipped tracking number delivery expected",
    "meeting scheduled for tomorrow please review the agenda attached",
    "monthly newsletter updates from our team this week highlights",
    "password changed successfully if you did not make this change",
    "welcome to the team onboarding documents please review policies",
    "invoice attached payment received thank you for your business",
    "your subscription has been renewed receipt attached no action needed",
]

# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────

def load_keywords(path="keywords.txt"):
    kws = []
    if not os.path.exists(path):
        with open(path, "w") as f:
            f.write(DEFAULT_KEYWORDS)
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(",")
            if len(parts) == 2:
                word, tier = parts[0].strip().lower(), parts[1].strip()
                if tier in ("1","2","3"):
                    kws.append((word, int(tier)))
    return kws

def extract_email_parts(filepath):
    """Returns (headers_dict, body_text, sender, subject)"""
    with open(filepath, "rb") as f:
        raw = f.read()
    try:
        msg = email.message_from_bytes(raw)
    except Exception:
        return {}, raw.decode(errors="replace"), "", ""
    
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            ct = part.get_content_type()
            if ct in ("text/plain","text/html"):
                payload = part.get_payload(decode=True) or b""
                try:
                    body += quopri.decodestring(payload).decode(errors="replace")
                except Exception:
                    body += payload.decode(errors="replace")
    else:
        payload = msg.get_payload(decode=True) or b""
        try:
            body = quopri.decodestring(payload).decode(errors="replace")
        except Exception:
            body = payload.decode(errors="replace")
    
    # strip HTML tags
    body = re.sub(r"<[^>]+>", " ", body)
    body = re.sub(r"\s+", " ", body).strip()
    
    headers = dict(msg.items())
    sender = msg.get("From","")
    subject = msg.get("Subject","")
    return headers, body, sender, subject

def extract_domain(email_str):
    m = re.search(r"@([\w.\-]+)", email_str)
    return m.group(1).lower() if m else ""

def tfidf_score(doc, corpus):
    """Simple TF-IDF cosine similarity of doc vs corpus (returns max similarity)"""
    def tokenize(text):
        return re.findall(r"\b[a-z]+\b", text.lower())
    
    all_docs = corpus + [doc]
    vocab = list(set(w for d in all_docs for w in tokenize(d)))
    if not vocab:
        return 0.0
    
    def tf(tokens, word):
        return tokens.count(word) / len(tokens) if tokens else 0
    
    def idf(word):
        containing = sum(1 for d in all_docs if word in tokenize(d))
        return math.log((len(all_docs)+1) / (containing+1)) + 1
    
    idf_map = {w: idf(w) for w in vocab}
    
    def vec(text):
        tokens = tokenize(text)
        return [tf(tokens,w) * idf_map[w] for w in vocab]
    
    def cosine(a, b):
        dot = sum(x*y for x,y in zip(a,b))
        na = math.sqrt(sum(x*x for x in a))
        nb = math.sqrt(sum(x*x for x in b))
        return dot/(na*nb) if na and nb else 0.0
    
    dv = vec(doc)
    return max(cosine(dv, vec(c)) for c in corpus)

# ─────────────────────────────────────────────
# DETECTION LAYERS
# ─────────────────────────────────────────────

def layer_phishing_tool(headers):
    """Hard override — if GoPhish/ZPhisher etc detected, instant flag"""
    xmailer = headers.get("X-Mailer","").lower()
    xphish  = headers.get("X-Phishing-Tool","").lower()
    combined = xmailer + " " + xphish
    for tool in PHISHING_TOOLS:
        if tool in combined:
            return True, tool
    return False, ""

def layer_keywords(body):
    score = 0
    reasons = []
    text = body.lower()
    
    tier1_found = any(kw in text for kw,t in KEYWORDS if t == 1)
    
    for kw, tier in KEYWORDS:
        if kw not in text:
            continue
        # TIER3 only counts if tier1 also present
        if tier == 3 and not tier1_found:
            continue
        # context window check (8 words around keyword)
        idx = text.find(kw)
        context = text[max(0,idx-40):idx+40]
        safe_ctx = ["successfully","no action","did not","you did","ignore this","completed","confirmed"]
        if any(s in context for s in safe_ctx):
            continue
        weight = {1:3, 2:2, 3:1}[tier]
        score += weight
        reasons.append(f"Keyword detected: '{kw}' (tier {tier})")
    
    return min(score, 30), reasons  # cap at 30

def layer_urls(body):
    score = 0
    reasons = []
    urls = re.findall(r"https?://[^\s\"'<>]+", body)
    
    for url in urls:
        # IP-based URL
        if re.search(r"https?://\d+\.\d+\.\d+\.\d+", url):
            score += 15
            reasons.append(f"IP-based URL found: {url[:60]}")
        # URL shortener
        for s in SHORTENERS:
            if s in url:
                score += 10
                reasons.append(f"URL shortener used: {s}")
                break
        # suspicious TLD
        for tld in SUSPICIOUS_TLDS:
            if re.search(re.escape(tld) + r"[/?]?", url):
                score += 10
                reasons.append(f"Suspicious TLD in URL: {tld}")
                break
    
    # hidden click-here links
    if re.search(r"click\s+here", body, re.I) and not urls:
        score += 5
        reasons.append("'Click here' with no visible URL")
    
    return min(score, 30), reasons

def layer_spoofing(sender, body, subject):
    score = 0
    reasons = []
    domain = extract_domain(sender)
    text = (body + " " + subject).lower()
    sender_l = sender.lower()
    
    # trusted domain — reduce risk
    trusted = any(domain.endswith(t.lstrip(".")) for t in TRUSTED_TLDS)
    if trusted:
        return -5, ["Trusted domain sender (.edu/.gov/.ac.pk) — reduced score"]
    
    # free provider + sensitive request
    free = ["gmail.com","yahoo.com","hotmail.com","outlook.com","live.com"]
    sensitive = ["bank detail","wire transfer","credit card","social security","password"]
    if any(f in domain for f in free) and any(s in text for s in sensitive):
        score += 15
        reasons.append("Free email provider asking for sensitive information")
    
    # brand impersonation
    display = re.search(r"^(.+?)\s*<", sender)
    display_name = display.group(1).lower() if display else ""
    for brand in KNOWN_BRANDS:
        if brand in display_name and brand not in domain:
            score += 20
            reasons.append(f"Brand impersonation: '{brand}' in name but not in domain")
            break
    
    # typosquatting
    for brand in KNOWN_BRANDS:
        if brand in text and domain:
            # simple Levenshtein-like: check if domain is 1 char off from brand
            for i in range(len(brand)):
                typo = brand[:i] + "." + brand[i+1:]  # char replaced
                if typo.replace(".","") in domain.replace(".",""):
                    score += 15
                    reasons.append(f"Possible typosquatting: domain looks like '{brand}'")
                    break
    
    # reply-to mismatch
    # (we pass headers separately if needed; skip here for simplicity)
    
    return min(score, 30), reasons

def layer_urgency(body):
    score = 0
    reasons = []
    text = body.lower()
    
    patterns = [
        (r"within\s+\d+\s+hours?",       10, "Artificial deadline (within N hours)"),
        (r"account\s+(will\s+be\s+)?(suspended|closed|blocked|terminated)",
                                          10, "Account suspension threat"),
        (r"legal\s+(action|proceeding)",  10, "Legal threat"),
        (r"(won|winner|selected|chosen).{0,30}(prize|reward|gift|lottery)",
                                          10, "Prize/lottery language"),
        (r"(verify|confirm).{0,20}(immediately|now|urgent|asap)",
                                           8, "Urgent verification request"),
        (r"do not\s+ignore",               5, "Do not ignore warning"),
        (r"last\s+(chance|warning|notice)", 8, "Last warning language"),
        (r"expires?\s+(in|on|at)",          5, "Expiry threat"),
    ]
    
    for pattern, pts, label in patterns:
        if re.search(pattern, text):
            score += pts
            reasons.append(label)
    
    return min(score, 30), reasons

def layer_tfidf(body):
    phish_sim = tfidf_score(body, PHISHING_CORPUS)
    safe_sim  = tfidf_score(body, SAFE_CORPUS)
    net = phish_sim - safe_sim
    score = max(0, round(net * 30))  # scale to max 30
    reasons = []
    if score > 5:
        reasons.append(f"Text similar to known phishing templates (net score: {net:.2f})")
    elif safe_sim > phish_sim:
        reasons.append(f"Text more similar to safe emails")
    return score, reasons

# ─────────────────────────────────────────────
# ORCHESTRATOR
# ─────────────────────────────────────────────

def analyze(filepath):
    global KEYWORDS
    KEYWORDS = load_keywords()
    
    headers, body, sender, subject = extract_email_parts(filepath)
    
    # Hard override
    tool_hit, tool_name = layer_phishing_tool(headers)
    if tool_hit:
        return {
            "verdict": "PHISHING",
            "confidence": 99,
            "reasons": [f"⚠ Phishing tool detected in headers: {tool_name}"],
            "scores": {"override": 99}
        }
    
    # Run layers
    s1, r1 = layer_keywords(body)
    s2, r2 = layer_urls(body)
    s3, r3 = layer_spoofing(sender, body, subject)
    s4, r4 = layer_urgency(body)
    s5, r5 = layer_tfidf(body)
    
    total = s1 + s2 + s3 + s4 + s5
    total = max(0, min(total, 100))
    
    all_reasons = r1 + r2 + r3 + r4 + r5
    
    if total >= 55:
        verdict = "PHISHING"
    elif total >= 25:
        verdict = "SUSPICIOUS"
    else:
        verdict = "SAFE"
    
    return {
        "verdict": verdict,
        "confidence": total,
        "reasons": all_reasons if all_reasons else ["No significant phishing indicators found."],
        "scores": {
            "Keywords": s1, "URLs": s2,
            "Sender Spoofing": s3, "Urgency/Threats": s4, "Text Similarity": s5
        }
    }

# ─────────────────────────────────────────────
# GUI
# ─────────────────────────────────────────────

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

COLORS = {
    "PHISHING":   "#e05555",
    "SUSPICIOUS": "#e0a020",
    "SAFE":       "#3dba6e",
}

class PhishScan(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("PhishScan — Phishing Email Detector")
        self.geometry("700x620")
        self.resizable(False, False)
        self._build_ui()

    def _build_ui(self):
        # Header
        ctk.CTkLabel(self, text="PhishScan", font=("Segoe UI", 28, "bold"),
                     text_color="#4da6ff").pack(pady=(24,2))
        ctk.CTkLabel(self, text="Intelligent Phishing Email Detection",
                     font=("Segoe UI", 13), text_color="#aaaaaa").pack(pady=(0,18))
        
        # Upload button
        self.upload_btn = ctk.CTkButton(
            self, text="📂  Upload Email File  (.eml / .txt)",
            font=("Segoe UI", 14), height=44, width=300,
            command=self._upload
        )
        self.upload_btn.pack(pady=6)
        
        self.file_label = ctk.CTkLabel(self, text="No file selected",
                                       font=("Segoe UI", 11), text_color="#888888")
        self.file_label.pack(pady=(4,16))
        
        # Verdict box
        self.verdict_frame = ctk.CTkFrame(self, width=620, height=100, corner_radius=14)
        self.verdict_frame.pack(padx=40, pady=6)
        self.verdict_frame.pack_propagate(False)
        
        self.verdict_label = ctk.CTkLabel(
            self.verdict_frame, text="—", font=("Segoe UI", 38, "bold"), text_color="#555555"
        )
        self.verdict_label.place(relx=0.5, rely=0.38, anchor="center")
        
        self.conf_label = ctk.CTkLabel(
            self.verdict_frame, text="", font=("Segoe UI", 13), text_color="#aaaaaa"
        )
        self.conf_label.place(relx=0.5, rely=0.75, anchor="center")
        
        # Score bars
        self.bars_frame = ctk.CTkFrame(self, width=620, corner_radius=12)
        self.bars_frame.pack(padx=40, pady=10, fill="x")
        self.bar_labels = {}
        self.bars = {}
        for i, layer in enumerate(["Keywords","URLs","Sender Spoofing","Urgency/Threats","Text Similarity"]):
            row = ctk.CTkFrame(self.bars_frame, fg_color="transparent")
            row.pack(fill="x", padx=14, pady=3)
            lbl = ctk.CTkLabel(row, text=f"{layer}:", font=("Segoe UI",11),
                               width=130, anchor="w")
            lbl.pack(side="left")
            bar = ctk.CTkProgressBar(row, width=280, height=14, corner_radius=6)
            bar.set(0)
            bar.pack(side="left", padx=8)
            val = ctk.CTkLabel(row, text="0/30", font=("Segoe UI",11), text_color="#aaaaaa")
            val.pack(side="left")
            self.bars[layer] = bar
            self.bar_labels[layer] = val
        
        # Reasons box
        ctk.CTkLabel(self, text="Detection Reasons:", font=("Segoe UI",12,"bold"),
                     anchor="w").pack(padx=40, pady=(10,2), fill="x")
        self.reasons_box = ctk.CTkTextbox(self, height=130, font=("Segoe UI",11),
                                          corner_radius=10)
        self.reasons_box.pack(padx=40, pady=(0,16), fill="x")
        self.reasons_box.configure(state="disabled")

    def _upload(self):
        path = fd.askopenfilename(
            title="Select Email File",
            filetypes=[("Email files","*.eml *.txt"),("All files","*.*")]
        )
        if not path:
            return
        self.file_label.configure(text=os.path.basename(path), text_color="#cccccc")
        try:
            result = analyze(path)
            self._show_result(result)
        except Exception as e:
            self._show_error(str(e))

    def _show_result(self, r):
        verdict = r["verdict"]
        color   = COLORS.get(verdict, "#ffffff")
        self.verdict_label.configure(text=verdict, text_color=color)
        self.conf_label.configure(text=f"Confidence Score: {r['confidence']}/100")
        
        scores = r.get("scores", {})
        for layer, bar in self.bars.items():
            s = max(0, scores.get(layer, 0))
            # spoofing can be negative — clamp
            bar.set(min(s/30, 1.0))
            self.bar_labels[layer].configure(text=f"{s}/30")
        
        self.reasons_box.configure(state="normal")
        self.reasons_box.delete("1.0","end")
        for i, r_ in enumerate(r["reasons"], 1):
            self.reasons_box.insert("end", f"{i}. {r_}\n")
        self.reasons_box.configure(state="disabled")

    def _show_error(self, msg):
        self.verdict_label.configure(text="ERROR", text_color="#ff6666")
        self.conf_label.configure(text="")
        self.reasons_box.configure(state="normal")
        self.reasons_box.delete("1.0","end")
        self.reasons_box.insert("end", f"Error: {msg}")
        self.reasons_box.configure(state="disabled")

if __name__ == "__main__":
    app = PhishScan()
    app.mainloop()
