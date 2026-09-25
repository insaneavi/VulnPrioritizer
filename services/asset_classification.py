def classify_asset(hostname, operating_system=""):
    name = str(hostname or "").strip().upper()
    os_value = str(operating_system or "").strip()
    os_upper = os_value.upper()

    # Specific hostname overrides must be evaluated before broad prefix rules.
    if name.startswith("HLSNY200") or name == "HLSNY201":
        return {"asset_group":"NetApp","location":"New York","management":"Internal","classification_source":"Hostname Override"}

    # Explicit Rapid7 OS identification takes precedence over broad hostname groups.
    if "VMWARE" in os_upper and "ESXI" in os_upper:
        return {"asset_group":"VMware ESXi Server","location":"UNKNOWN","management":"Internal","classification_source":"Rapid7 OS"}

    rules = [
        ("LHT", {"asset_group":"IBM iSeries","location":"UNKNOWN","management":"Internal"}),
        ("NYP", {"asset_group":"Printer","location":"New York","management":"Internal"}),
        ("NYL", {"asset_group":"Laptop","location":"New York","management":"Internal"}),
        ("HLSNY", {"asset_group":"Server","location":"New York","management":"Internal"}),
        ("HLSI", {"asset_group":"Domain Controller","location":"UNKNOWN","management":"Other Team"}),
        ("SLD", {"asset_group":"Server","location":"London","management":"Internal"}),
    ]
    for prefix, values in rules:
        if name.startswith(prefix):
            return {**values, "classification_source":"Hostname Rule"}

    return {"asset_group":"UNKNOWN","location":"UNKNOWN","management":"UNKNOWN","classification_source":"Hostname Rule - No Match"}
