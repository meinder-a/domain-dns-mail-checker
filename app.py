"""
This module sets up a Flask web application to check domain DNS configurations (on mail aspects) for domains.
"""

from flask import Flask, render_template, jsonify
from dns_check import check_dns

app = Flask(__name__)

@app.route('/')
def index():
    """Render the main page of the web application."""
    return render_template('index.html')

@app.route('/dns-check/<domain>')
def dns_check(domain):
    """
    Perform a DNS check for the given domain.
    :param domain: Domain name to check.
    :return: JSON response of the DNS check results.
    """
    result = check_dns(domain)
    return jsonify(result)

if __name__ == '__main__':
    app.run(debug=False)
