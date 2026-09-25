import re

RULES = [
    (re.compile(r'^NYP\d{4}$', re.I), {'asset_group':'Printer','location':'New York','management':'Internal'}),
    (re.compile(r'^NYL\d{4}$', re.I), {'asset_group':'Laptop','location':'New York','management':'Internal'}),
    (re.compile(r'^HLSNY\d{4}$', re.I), {'asset_group':'Server','location':'New York','management':'Internal'}),
    (re.compile(r'^HLSI\d{3}$', re.I), {'asset_group':'Domain Controller','location':'Unknown','management':'Other Team'}),
    (re.compile(r'^SLD\d{4}$', re.I), {'asset_group':'Server','location':'London','management':'Internal'}),
]

def classify_asset(hostname):
    name=(hostname or '').strip()
    for pattern, values in RULES:
        if pattern.fullmatch(name):
            return {**values, 'classification_source':'Hostname Rule'}
    return {'asset_group':'UNKNOWN','location':'UNKNOWN','management':'UNKNOWN','classification_source':'Hostname Rule - No Match'}
