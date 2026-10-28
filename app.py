"""PhishShield web application + REST API.

Run:  python app.py      then open http://127.0.0.1:5000
"""
import json
import os

from flask import Flask, abort, jsonify, render_template, request, send_from_directory

from config import REPORT_DIR, ROOT
from phishshield import __version__, engine, storage

MAX_UPLOAD_MB = 5
QUIZ = json.loads((ROOT / "awareness" / "quiz.json").read_text(encoding="utf-8"))


def create_app(db_path=None):
    app = Flask(__name__, template_folder="web/templates", static_folder="web/static")
    app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_MB * 1024 * 1024
    app.config["DB_PATH"] = db_path

    # Load models at start-up so the first visitor doesn't wait for them.
    for channel in ("sms", "email", "url"):
        try:
            engine.load_model(channel)
        except FileNotFoundError:
            pass

    def db():
        return app.config["DB_PATH"]

    def model_reports():
        reports = {}
        for ch in ("sms", "email", "url", "qr"):
            p = REPORT_DIR / f"{ch}_metrics.json"
            if p.exists():
                reports[ch] = json.loads(p.read_text())
        return reports

    # ---------- pages ----------
    @app.route("/")
    def home():
        return render_template("home.html", stats=storage.stats(db()), reports=model_reports())

    @app.route("/scan")
    def scan_page():
        return render_template("scan.html", tab=request.args.get("tab", "sms"))

    @app.route("/training")
    def training():
        public = [{k: v for k, v in q.items() if k not in ("answer", "explanation", "clues")} for q in QUIZ]
        return render_template("training.html", questions=public)

    @app.route("/learn")
    def learn():
        return render_template("learn.html")

    @app.route("/dashboard")
    def dashboard():
        return render_template("dashboard.html", stats=storage.stats(db()), reports=model_reports())

    @app.route("/about")
    def about():
        return render_template("about.html", reports=model_reports(), version=__version__)

    @app.route("/reports/<path:name>")
    def report_file(name):
        if not name.endswith(".png"):
            abort(404)
        return send_from_directory(REPORT_DIR, name)

    @app.route("/samples/qr/<path:name>")
    def sample_qr(name):
        return send_from_directory(ROOT / "samples" / "qr", name)

    # ---------- REST API ----------
    def payload_text(field):
        if request.is_json:
            return (request.get_json(silent=True) or {}).get(field, "")
        return request.form.get(field, "")

    def respond(result, preview):
        storage.log_scan(result, preview, db())
        return jsonify(result)

    @app.post("/api/v1/scan/sms")
    def api_sms():
        text = payload_text("text").strip()
        if not text:
            return jsonify(error="Field 'text' is required."), 400
        return respond(engine.analyze_sms(text), text)

    @app.post("/api/v1/scan/url")
    def api_url():
        url = payload_text("url").strip()
        if not url or " " in url:
            return jsonify(error="Field 'url' must be a single URL."), 400
        return respond(engine.analyze_url(url), url)

    @app.post("/api/v1/scan/email")
    def api_email():
        file = request.files.get("file")
        if file and file.filename:
            raw = file.read()
        else:
            raw = payload_text("email").strip()
            if not raw:
                return jsonify(error="Provide 'email' text or an .eml 'file'."), 400
        result = engine.analyze_email(raw)
        return respond(result, result["details"].get("subject") or str(raw[:120]))

    @app.post("/api/v1/scan/qr")
    def api_qr():
        file = request.files.get("file")
        if file and file.filename:
            result = engine.analyze_qr_image(file.read())
        else:
            payload = payload_text("payload").strip()
            if not payload:
                return jsonify(error="Upload an image 'file' or send the decoded 'payload'."), 400
            result = engine.analyze_qr_payload(payload)
        if result["verdict"] == "unknown":
            return jsonify(result)
        return respond(result, result["details"].get("qr_payload", ""))

    @app.post("/api/v1/quiz/answer")
    def api_quiz_answer():
        data = request.get_json(silent=True) or {}
        q = next((q for q in QUIZ if q["id"] == data.get("id")), None)
        if not q:
            return jsonify(error="Unknown question"), 404
        return jsonify(correct=data.get("answer") == q["answer"], answer=q["answer"],
                       explanation=q["explanation"], clues=q["clues"])

    @app.post("/api/v1/quiz/submit")
    def api_quiz_submit():
        data = request.get_json(silent=True) or {}
        score, total = int(data.get("score", 0)), len(QUIZ)
        storage.log_quiz(str(data.get("nickname", "")), max(0, min(score, total)), total, db())
        return jsonify(ok=True)

    @app.get("/api/v1/stats")
    def api_stats():
        return jsonify(storage.stats(db()))

    @app.get("/api/v1/health")
    def health():
        return jsonify(status="ok", version=__version__, models=list(model_reports()))

    @app.errorhandler(413)
    def too_large(_):
        return jsonify(error=f"File too large (max {MAX_UPLOAD_MB} MB)."), 413

    @app.errorhandler(FileNotFoundError)
    def no_model(e):
        return jsonify(error=str(e)), 503

    @app.errorhandler(ValueError)
    def bad_input(e):
        return jsonify(error=str(e)), 400

    return app


if __name__ == "__main__":
    create_app().run(debug=False, port=int(os.environ.get("PORT", 5000)))
