import requests

API_KEY = "80c2cc77c086792838ee22fbb73523185b12d1f4eff3ac26c03a8e6bdd510f5c"

def check_virustotal(url):
    try:
        headers = {"x-apikey": API_KEY}

        # URL submit பண்ணு
        response = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": url}
        )

        if response.status_code != 200:
            return {"error": "Could not submit URL"}

        # Analysis ID எடு
        analysis_id = response.json()["data"]["id"]

        # Result எடு
        result = requests.get(
            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
            headers=headers
        )

        if result.status_code != 200:
            return {"error": "Could not fetch results"}

        stats = result.json()["data"]["attributes"]["stats"]

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        total = malicious + suspicious + harmless

        if malicious >= 3:
            verdict = "🔴 Malicious"
        elif malicious >= 1 or suspicious >= 2:
            verdict = "🟡 Suspicious"
        else:
            verdict = "🟢 Clean"

        return {
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "total": total,
            "verdict": verdict,
            "error": None
        }

    except Exception as e:
        return {"error": str(e)}