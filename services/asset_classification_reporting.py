from io import BytesIO
from datetime import datetime
import xlsxwriter

STATUS_COLORS={"Current":"#DCFCE7","Aging":"#FEF3C7","Stale":"#FECACA","Unknown":"#E5E7EB"}
STATUS_FONT={"Current":"#14532D","Aging":"#713F12","Stale":"#7F1D1D","Unknown":"#374151"}

def build_asset_classification_report(analysis):
    output=BytesIO()
    wb=xlsxwriter.Workbook(output,{"in_memory":True})
    title=wb.add_format({"bold":True,"font_size":18,"font_color":"#FFFFFF","bg_color":"#17233D","align":"left","valign":"vcenter"})
    header=wb.add_format({"bold":True,"font_color":"#FFFFFF","bg_color":"#17233D","border":1,"border_color":"#293956"})
    body=wb.add_format({"border":1,"border_color":"#D7DEE9"})
    unknown=wb.add_format({"bold":True,"font_color":"#7F1D1D","bg_color":"#FECACA","border":1,"border_color":"#D7DEE9"})
    muted=wb.add_format({"font_color":"#5B6577","italic":True})
    generated=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    assets=analysis.get("assets_table",[])

    summary=wb.add_worksheet("Classification Summary")
    summary.set_column("A:A",30); summary.set_column("B:B",18); summary.set_column("D:F",28)
    summary.merge_range("A1:F1","VulnPrioritizer Asset Classification Review",title); summary.set_row(0,28)
    summary.write("A3","Generated",header); summary.write("B3",generated,body)
    summary.write("A4","Total Assets",header); summary.write("B4",len(assets),body)
    unknown_count=sum(1 for a in assets if a.get("asset_group")=="UNKNOWN")
    summary.write("A5","UNKNOWN Assets",header); summary.write("B5",unknown_count,unknown if unknown_count else body)
    summary.write("A7","Asset Group",header); summary.write("B7","Count",header)
    counts={}
    for a in assets: counts[a.get("asset_group","UNKNOWN")]=counts.get(a.get("asset_group","UNKNOWN"),0)+1
    for i,(group,count) in enumerate(sorted(counts.items()),8):
        summary.write(i-1,0,group,unknown if group=="UNKNOWN" else body); summary.write(i-1,1,count,body)
    summary.write("D3","Purpose",header); summary.merge_range("D4:F6","Audit the operational asset tags derived from Rapid7 hostname and OS data. UNKNOWN assets are intentionally exposed for research rather than guessed.",muted)

    headers=["Hostname","IP Address","Rapid7 Asset ID","Asset Group","Location","Management","Classification Source","Classification Rule","Rapid7 Operating System","Last Scan","Scan Age (Days)","Scan Status"]
    def detail_sheet(name, rows):
        ws=wb.add_worksheet(name); ws.freeze_panes(1,0); ws.autofilter(0,0,max(1,len(rows)),len(headers)-1)
        widths=[22,16,18,22,14,16,22,30,36,21,15,14]
        for c,w in enumerate(widths): ws.set_column(c,c,w)
        for c,h in enumerate(headers): ws.write(0,c,h,header)
        for r,a in enumerate(rows,1):
            values=[a.get("hostname"),a.get("ip_address"),a.get("asset_id"),a.get("asset_group"),a.get("location"),a.get("management"),a.get("classification_source"),a.get("classification_rule"),a.get("operating_system"),a.get("last_scan_timestamp") or "",a.get("scan_age_days"),a.get("scan_status")]
            for c,v in enumerate(values):
                fmt=unknown if (c==3 and a.get("asset_group")=="UNKNOWN") else body
                if c==11:
                    status=a.get("scan_status","Unknown"); fmt=wb.add_format({"bold":True,"font_color":STATUS_FONT.get(status,"#374151"),"bg_color":STATUS_COLORS.get(status,"#E5E7EB"),"border":1,"border_color":"#D7DEE9"})
                ws.write(r,c,"" if v is None else v,fmt)
        return ws
    detail_sheet("Classification Detail",assets)
    detail_sheet("UNKNOWN Assets",[a for a in assets if a.get("asset_group")=="UNKNOWN"])
    wb.close(); output.seek(0); return output
