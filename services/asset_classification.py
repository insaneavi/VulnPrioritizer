ASSET_CLASSIFICATION_RULES = [
    {"priority":1,"detection":"HLSNY200* or exact HLSNY201","asset_group":"NetApp","location":"New York","management":"Internal","source":"Hostname Override"},
    {"priority":2,"detection":"Rapid7 OS identifies VMware ESXi","asset_group":"VMware ESXi Server","location":"UNKNOWN","management":"Internal","source":"Rapid7 OS"},
    {"priority":3,"detection":"LHT*","asset_group":"IBM iSeries","location":"UNKNOWN","management":"Internal","source":"Hostname Rule"},
    {"priority":4,"detection":"NYP*","asset_group":"Printer","location":"New York","management":"Internal","source":"Hostname Rule"},
    {"priority":5,"detection":"NYL*","asset_group":"Laptop","location":"New York","management":"Internal","source":"Hostname Rule"},
    {"priority":6,"detection":"HLSNY*","asset_group":"Server","location":"New York","management":"Internal","source":"Hostname Rule"},
    {"priority":7,"detection":"HLSI*","asset_group":"Domain Controller","location":"UNKNOWN","management":"Other Team","source":"Hostname Rule"},
    {"priority":8,"detection":"SLD*","asset_group":"Server","location":"London","management":"Internal","source":"Hostname Rule"},
    {"priority":9,"detection":"No defined match","asset_group":"UNKNOWN","location":"UNKNOWN","management":"UNKNOWN","source":"No Match"},
]

def classify_asset(hostname, operating_system=""):
    name = str(hostname or "").strip().upper()
    os_value = str(operating_system or "").strip()
    os_upper = os_value.upper()
    if name.startswith("HLSNY200") or name == "HLSNY201":
        return {"asset_group":"NetApp","location":"New York","management":"Internal","classification_source":"Hostname Override","classification_rule":"HLSNY200* / exact HLSNY201"}
    if "VMWARE" in os_upper and "ESXI" in os_upper:
        return {"asset_group":"VMware ESXi Server","location":"UNKNOWN","management":"Internal","classification_source":"Rapid7 OS","classification_rule":"OS contains VMware + ESXi"}
    rules = [
        ("LHT", "IBM iSeries", "UNKNOWN", "Internal", "LHT*"),
        ("NYP", "Printer", "New York", "Internal", "NYP*"),
        ("NYL", "Laptop", "New York", "Internal", "NYL*"),
        ("HLSNY", "Server", "New York", "Internal", "HLSNY*"),
        ("HLSI", "Domain Controller", "UNKNOWN", "Other Team", "HLSI*"),
        ("SLD", "Server", "London", "Internal", "SLD*"),
    ]
    for prefix, group, location, management, rule in rules:
        if name.startswith(prefix):
            return {"asset_group":group,"location":location,"management":management,"classification_source":"Hostname Rule","classification_rule":rule}
    return {"asset_group":"UNKNOWN","location":"UNKNOWN","management":"UNKNOWN","classification_source":"No Match","classification_rule":"No defined match"}
