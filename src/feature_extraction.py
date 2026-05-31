import re
import tldextract

def extract_features(url):
    features = {}
    ext = tldextract.extract(url)

    # UsingIP
    features['UsingIP'] = -1 if re.search(
        r'\d+\.\d+\.\d+\.\d+', url) else 1

    # LongURL
    length = len(url)
    features['LongURL'] = -1 if length > 75 else (
        0 if length >= 54 else 1)

    # ShortURL
    shorteners = ['bit.ly', 'tinyurl', 'goo.gl', 't.co']
    features['ShortURL'] = -1 if any(
        s in url for s in shorteners) else 1

    # Symbol@
    features['Symbol@'] = -1 if '@' in url else 1

    # Redirecting//
    features['Redirecting//'] = -1 if '//' in url[7:] else 1

    # PrefixSuffix-
    features['PrefixSuffix-'] = -1 if '-' in ext.domain else 1

    # SubDomains
    subs = ext.subdomain.split('.') if ext.subdomain else []
    features['SubDomains'] = -1 if len(subs) > 2 else (
        0 if len(subs) == 2 else 1)

    # HTTPS
    features['HTTPS'] = 1 if url.startswith('https') else -1

    # DomainRegLen
    features['DomainRegLen'] = 1 if len(ext.domain) > 6 else -1

    # Favicon
    features['Favicon'] = 1

    # NonStdPort
    features['NonStdPort'] = -1 if re.search(
        r':\d{4,5}', url) else 1

    # HTTPSDomainURL
    features['HTTPSDomainURL'] = -1 if 'https' in ext.domain else 1

    # RequestURL
    features['RequestURL'] = 1

    # AnchorURL
    features['AnchorURL'] = 1

    # LinksInScriptTags
    features['LinksInScriptTags'] = 1

    # ServerFormHandler
    features['ServerFormHandler'] = 1

    # InfoEmail
    features['InfoEmail'] = -1 if 'mailto:' in url else 1

    # AbnormalURL
    features['AbnormalURL'] = -1 if ext.domain not in url else 1

    # WebsiteForwarding
    features['WebsiteForwarding'] = 1

    # StatusBarCust
    features['StatusBarCust'] = 1

    # DisableRightClick
    features['DisableRightClick'] = 1

    # UsingPopupWindow
    features['UsingPopupWindow'] = 1

    # IframeRedirection
    features['IframeRedirection'] = 1

    # AgeofDomain
    features['AgeofDomain'] = 1

    # DNSRecording
    features['DNSRecording'] = 1

    # WebsiteTraffic
    features['WebsiteTraffic'] = 1

    # PageRank
    features['PageRank'] = 1

    # GoogleIndex
    features['GoogleIndex'] = 1

    # LinksPointingToPage
    features['LinksPointingToPage'] = 1

    # StatsReport
    features['StatsReport'] = 1

    return features