from flask import Flask, render_template, request
from detector import detect_phishing

app = Flask(__name__)


@app.route("/", methods=["GET", "POST"])
def home():

    if request.method == "POST":

        url = request.form.get("url", "").strip()

        if not url:
            return render_template(
                "index.html",
                error="Please enter a URL."
            )

        result = detect_phishing(url)

        return render_template(
            "result.html",
            url=url,
            result=result
        )

    return render_template("index.html")


if __name__ == "__main__":
    app.run(debug=True)