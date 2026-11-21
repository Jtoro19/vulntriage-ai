"""Tiny inventory app for the lab. It is harmless; the risk is in the pinned library versions."""

from flask import Flask, render_template_string

app = Flask(__name__)


@app.get("/")
def index():
    return render_template_string("<h1>Lab inventory service</h1><p>Status: {{ status }}</p>",
                                  status="ok")


if __name__ == "__main__":
    # Werkzeug development server (debugger disabled); reachable only on the lab network.
    app.run(host="0.0.0.0", port=5000, debug=False)
