"""
run.py — Entry point for the application.

Use this instead of `python app.py` to avoid the double-import issue.
When this file is __main__, `app.py` is cleanly imported as the `app` module,
so routes.py's `from app import app` gets the same Flask instance.

Run with:
    python run.py
"""
from app import app

if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5000, use_reloader=False)

