# CyberGuard Pro: Your All-in-One Security Intelligence Hub

![CyberGuard Pro Dashboard](./static/assets/screenshots/dashboard_home.png)

In an era where digital threats evolve daily, staying ahead of phishing and credential-based attacks is no longer optional. **CyberGuard Pro** is my answer to this challenge—a comprehensive security toolkit built to analyze, generate, and report on the digital footprints that matter most.

Whether you're investigating a suspicious link or hardening your personal credentials, CyberGuard Pro provides the deep-tier analysis needed to stay safe.

---

## 🔍 Core Security Pillars

### 1. Advanced URL Forensics
Most scanners just check a blacklist. CyberGuard Pro goes deeper. It interrogates the URL from multiple angles to identify even zero-day phishing sites.

*   **SSL/TLS Integrity**: Real-time validation of certificate chains and expiry dates.
*   **Domain Origin**: Leverages WHOIS data to flag "sandboxed" or newly registered domains (common in phishing).
*   **Network Intelligence**: Performs deep DNS interrogation (A, MX, NS records) and common service port scans.
*   **Reputation Algorithm**: A multi-factor scoring system that analyzes URL structure, character entropy, and security headers like HSTS and CSP.

#### Detection Examples:
| Status | Analysis Result |
| :--- | :--- |
| **Phishing Detected** | ![Phishing Example](./static/assets/screenshots/url_phishing.png) |
| **Safe Domain** | ![Safe Example](./static/assets/screenshots/url_safe.png) |

### 2. Credential Intelligence & Generation
Security starts with a strong foundation. Our password suite isn't just a random character generator—it's a strength intelligence engine.

*   **Entropy Scoring**: Move beyond "Weak/Strong" to mathematical entropy bits.
*   **Pattern Detection**: Flags common sequences, dictionary words, and keyboard walks.
*   **Contextual Generation**: Generate highly secure passwords that can actually be memorable, or go for maximum entropy with our secure-pool generator.

![Password Intelligence Dashboard](./static/assets/screenshots/password_strength.png)

### 3. Enterprise Reporting
Security is only as good as its documentation. CyberGuard Pro generates professional-grade PDF and CSV reports for every analysis, making it easy to share findings with teams or keep for your own audit trails.

---

## 🛠️ The Technical Blueprint

This project was built with a focus on **speed, security, and scalability**.

*   **Engine**: Python 3.11 + Flask (Micro-framework flexibility)
*   **Storage**: MySQL + SQLAlchemy (Structured, relational audit trails)
*   **Visuals**: Vanilla CSS3 + Modern JavaScript (Fast, responsive, and dependency-light)
*   **Analysis Libraries**: `ReportsLab` (Document engine), `Whois`, `DNSPython`, and `Requests`.

---

## ⚙️ Getting Started

### Prerequisites
*   Python 3.11+
*   MySQL (XAMPP recommended)
*   A curious mind

### Quick Setup

1.  **Clone the Repository**
    ```bash
    git clone https://github.com/yourusername/CyberGuard-Pro.git
    cd CyberGuard-Pro
    ```

2.  **Environment Sync**
    ```bash
    python -m venv venv
    source venv/bin/activate  # Windows: venv\Scripts\activate
    pip install -r requirements.txt
    ```

3.  **Database Connection**
    Create a MySQL database named `cyberguardpro`. In `app.py`, update your connection string:
    ```python
    app.config["SQLALCHEMY_DATABASE_URI"] = "mysql+pymysql://root:password@localhost/cyberguardpro"
    ```

4.  **Launch**
    ```bash
    python app.py
    ```
    Head to `http://127.0.0.1:5000` to start scanning.

---

## 🤝 Project Roadmap
*   [ ] Multi-user team workspaces
*   [ ] API access for external integrations
*   [ ] Live browser extension for real-time URL flagging

---

*Prepared with care by a developer who cares about secure code.*
