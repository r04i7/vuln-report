from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from models import init_db, get_db_connection
from parser import parse_and_import_xml
import os

app = Flask(__name__, static_folder="static", template_folder="templates")
CORS(app)

# Initialize DB safely (Gunicorn safe)
with app.app_context():
    init_db()


# -------------------- FRONTEND --------------------
@app.route("/")
def home():
    return send_from_directory("templates", "index.html")


# -------------------- HEALTH CHECK --------------------
@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({"status": "ok"})


# -------------------- SEARCH VULNERABILITY --------------------
@app.route('/api/search', methods=['GET'])
def search():
    query = request.args.get('q', '').strip()

    if not query or len(query) < 2:
        return jsonify([])

    try:
        conn = get_db_connection()
        c = conn.cursor()

        sql = """
            SELECT * FROM vulnerabilities
            WHERE title LIKE ? OR id LIKE ?
            LIMIT 10
        """

        search_term = f"%{query}%"
        c.execute(sql, (search_term, search_term))
        rows = c.fetchall()
        conn.close()

        results = []
        for row in rows:
            results.append({
                "id": row["id"],
                "title": row["title"],
                "description": row["description"],
                "impact": row["impact"],
                "remediation": row["remediation"],
                "cwe": row["cwe"],
                "cvss": row["cvss_vector"],
                "likelihood": row["likelihood"],
                "severity": row["severity"]
            })

        return jsonify(results)

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# -------------------- IMPORT XML KB --------------------
@app.route('/api/import', methods=['POST'])
def import_xml():
    if 'file' not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files['file']

    if file.filename == '':
        return jsonify({"error": "Empty filename"}), 400

    try:
        content = file.stream.read().decode("utf-8")
        result = parse_and_import_xml(content, is_content=True)
        return jsonify(result)

    except UnicodeDecodeError:
        return jsonify({"error": "Invalid XML encoding"}), 400

    except Exception as e:
        return jsonify({"error": f"Import failed: {str(e)}"}), 500


# -------------------- START SERVER (LOCAL ONLY) --------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
