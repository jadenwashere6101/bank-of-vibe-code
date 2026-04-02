#  Bank of a Vibe Code

A security-focused full-stack banking application built in ~5 days and deployed to a live Azure VM.

- Built with **Flask, MySQL, Docker, Nginx**
- Hardened against common **OWASP-style web risks**
- Includes **CI/CD with automated OWASP ZAP security scanning**
- Designed around real-world failure scenarios like **race conditions, financial precision, and abuse prevention**

## 📄 Case Study

[View the full case study](./WRITEUP.pdf)

This project was developed with AI as a tool, but all architectural decisions, security validations, and fixes were manually directed and verified.

## Tech Stack

### Backend
- Python (Flask)
- Gunicorn (WSGI server, multi-worker)

### Database
- MySQL (parameterized queries, transactional integrity)

### Frontend
- HTML (Jinja2 templates)

### Infrastructure
- Nginx (reverse proxy, HTTPS termination)
- Docker (containerized application)
- Azure VM (cloud hosting)

##  System Architecture
User → Nginx (HTTPS, headers) → Gunicorn (4 workers) → Flask app → MySQL

## Scalability Notes
The current setup is designed for moderate traffic on a single Azure VM. Gunicorn uses multiple workers to handle concurrent requests, but larger-scale traffic would require multiple app instances behind a load balancer and a shared backend such as Redis for session/state management.

## 🔐 Security Features

- **CSRF Protection (Flask-WTF)**  
  Prevents unauthorized form submissions from external sites.
- **Rate Limiting (Flask-Limiter)**  
  Limits repeated requests to prevent brute-force attacks.
- **Per-Account Lockout**  
  Locks accounts after multiple failed login attempts to stop credential stuffing.
- **Session Security**  
  Uses HTTPOnly, Secure, and SameSite cookies to protect session data from theft.
- **Password Hashing (Werkzeug)**  
  Passwords are securely hashed and never stored in plaintext.
- **Atomic Database Transactions**  
  Prevents race conditions in financial operations like deposit/withdraw.
- **Decimal-Based Calculations**  
  Avoids floating-point precision errors in financial data.
- **Security Headers (Nginx)**  
  Includes HSTS, CSP, and X-Frame-Options to protect against common web attacks.

### DevSecOps / CI-CD
- GitHub Actions (automated deployment)
- OWASP ZAP (automated security scanning on every push)
- SSH-based deployment pipeline to Azure VM
