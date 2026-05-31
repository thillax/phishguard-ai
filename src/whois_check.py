import whois
from datetime import datetime

def check_domain_age(url):
    try:
        domain = url.replace('https://', '').replace(
            'http://', '').split('/')[0]

        # IP address-ஆ இருந்தா skip பண்ணு
        import re
        if re.match(r'\d+\.\d+\.\d+\.\d+', domain):
            return {'error': 'IP address — no domain to lookup'}

        w = whois.whois(domain)

        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        expiry_date = w.expiration_date
        if isinstance(expiry_date, list):
            expiry_date = expiry_date[0]

        if creation_date is None:
            return {'error': 'Creation date not found'}

        age_days = (datetime.now() - creation_date).days
        age_months = age_days // 30

        if age_days < 30:
            risk = "🔴 Very High Risk"
        elif age_days < 180:
            risk = "🟡 Medium Risk"
        else:
            risk = "🟢 Low Risk"

        return {
            'domain': domain,
            'creation_date': str(creation_date)[:10],
            'expiry_date': str(expiry_date)[:10]
                           if expiry_date else 'Unknown',
            'age_days': age_days,
            'age_months': age_months,
            'risk': risk,
            'error': None
        }

    except Exception as e:
        return {
            'domain': url,
            'error': str(e),
            'risk': '⚠️ Could not fetch'
        }