# Minimal Flask app pinned to versions with known CVEs (lab use only):
# Werkzeug 2.2.2 (CVE-2023-25577, CVE-2023-23934), Jinja2 3.1.2 (CVE-2024-22195).
FROM python:3.11-slim
RUN pip install --no-cache-dir flask==2.2.2 werkzeug==2.2.2 jinja2==3.1.2
WORKDIR /app
COPY app.py .
EXPOSE 5000
CMD ["python", "app.py"]
