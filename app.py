from flask import Flask, render_template, request
from core.engine import run_scan

app = Flask(__name__)


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():

    target = request.form.get("target")

    try:
        results = run_scan(target)

        return render_template(
            "results.html",
            results=results
        )

    except Exception as e:
        return render_template(
            "results.html",
            error=str(e)
        )


if __name__ == "__main__":
    app.run(debug=True)
