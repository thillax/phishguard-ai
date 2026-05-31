from flask import Flask, request, jsonify, render_template
import joblib
import pandas as pd
import sys
import re
import ssl
import socket
from datetime import datetime
sys.path.append('src')
from feature_extraction import extract_features
from whois_check import check_domain_age

app = Flask(__name__)

model = joblib.load('model/phishing_model.pkl')

def get_risk_score(features):
    weights = {
        'UsingIP': 3, 'HTTPS': 2, 'Symbol@': 2,
        'SubDomains': 1.5, 'LongURL': 1, 'ShortURL': 1,
        'Redirecting//': 1, 'PrefixSuffix-': 1,
        'NonStdPort': 1, 'InfoEmail': 1,
    }
    score = sum(w for f, w in weights.items()
                if features.get(f) == -1)
    risk_score = round(min(score, 10), 1)
    sus_count = sum(1 for v in features.values() if v == -1)
    if risk_score >= 5:
        return "High", sus_count, risk_score
    elif risk_score >= 2:
        return "Medium", sus_count, risk_score
    else:
        return "Low", sus_count, risk_score

def get_reasons(features):
    reasons = []
    if features['UsingIP'] == -1:
        reasons.append("IP address used instead of domain name")
    if features['LongURL'] == -1:
        reasons.append("Suspicious URL length detected")
    if features['ShortURL'] == -1:
        reasons.append("URL shortener detected")
    if features['Symbol@'] == -1:
        reasons.append("@ symbol found in URL")
    if features['Redirecting//'] == -1:
        reasons.append("Multiple redirects detected")
    if features['PrefixSuffix-'] == -1:
        reasons.append("Hyphen found in domain name")
    if features['SubDomains'] == -1:
        reasons.append("Too many subdomains detected")
    if features['HTTPS'] == -1:
        reasons.append("No HTTPS encryption")
    if features['NonStdPort'] == -1:
        reasons.append("Non-standard port detected")
    if features['InfoEmail'] == -1:
        reasons.append("Email address found in URL")
    if not reasons:
        reasons.append("No suspicious patterns detected")
    return reasons

def is_ip(url):
    domain = url.replace('https://', '').replace(
        'http://', '').split('/')[0]
    return bool(re.match(r'\d+\.\d+\.\d+\.\d+', domain))

def check_ssl(url):
    try:
        domain = url.replace('https://', '').replace(
            'http://', '').split('/')[0]
        if is_ip(url):
            return {'error': 'IP address'}
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(
            socket.socket(), server_hostname=domain) as s:
            s.settimeout(5)
            s.connect((domain, 443))
            cert = s.getpeercert()
            expiry = datetime.strptime(
                cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
            days_left = (expiry - datetime.now()).days
            return {
                'valid': True,
                'expiry': expiry.strftime('%Y-%m-%d'),
                'days_left': days_left,
                'error': None
            }
    except Exception as e:
        return {'valid': False, 'error': str(e)}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.get_json()
    url = data.get('url', '').strip()
    if not url:
        return jsonify({'error': 'No URL provided'}), 400

    features = extract_features(url)
    input_df = pd.DataFrame([features])
    confidence = model.predict_proba(input_df)[0]
    reasons = get_reasons(features)
    risk_label, sus_count, risk_score = get_risk_score(features)
    conf = round(max(confidence) * 100, 1)

    ssl_result = check_ssl(url)

    whois_result = {'error': 'IP address'} if is_ip(url) else check_domain_age(url)

    indicators = {
        'IP Address Usage': features['UsingIP'] == -1,
        'HTTPS Missing': features['HTTPS'] == -1,
        '@ Symbol Found': features['Symbol@'] == -1,
        'URL Shortener': features['ShortURL'] == -1,
        'Multiple Redirects': features['Redirecting//'] == -1,
        'Hyphen in Domain': features['PrefixSuffix-'] == -1,
        'Excessive Subdomains': features['SubDomains'] == -1,
    }

    verdict = 'PHISHING' if risk_score >= 5 else 'SUSPICIOUS' if risk_score >= 2 else 'SAFE'

    return jsonify({
        'url': url,
        'verdict': verdict,
        'confidence': conf,
        'risk_level': risk_label,
        'risk_score': risk_score,
        'reasons': reasons,
        'indicators': indicators,
        'ssl': ssl_result,
        'whois': whois_result,
    })

if __name__ == '__main__':
    app.run(debug=True)