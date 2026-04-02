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

## 📈 Scalability Notes
The current setup is designed for moderate traffic on a single Azure VM. Gunicorn uses multiple workers to handle concurrent requests, but larger-scale traffic would require multiple app instances behind a load balancer and a shared backend such as Redis for session/state management.

### Security
- CSRF protection (Flask-WTF)
- Rate limiting (Flask-Limiter)
- Per-account lockout system
- Session security (HTTPOnly, Secure, SameSite cookies)
- Password hashing (Werkzeug / bcrypt)
- Atomic database transactions (race condition protection)
- Decimal-based financial calculations (no floating-point errors)
- Security headers (HSTS, CSP, X-Frame-Options, etc.)

### DevSecOps / CI-CD
- GitHub Actions (automated deployment)
- OWASP ZAP (automated security scanning on every push)
- SSH-based deployment pipeline to Azure VM
