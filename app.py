from flask import Flask, render_template, jsonify
from dns_check import check_dns

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/dns-check/<domain>')
def dns_check(domain):
    result = check_dns(domain)
    return jsonify(result)

if __name__ == '__main__':
    app.run(debug=False)
