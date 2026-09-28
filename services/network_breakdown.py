import ipaddress
from collections import Counter, defaultdict
from io import BytesIO
from datetime import datetime
from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment
from openpyxl.utils import get_column_letter

DEFAULT_PREFIX = 24
ALLOWED_PREFIXES = tuple(range(8, 33))

def normalize_prefix(value):
    try: p=int(value)
    except (TypeError, ValueError): return DEFAULT_PREFIX
    return p if p in ALLOWED_PREFIXES else DEFAULT_PREFIX

def build_network_breakdown(assets, prefix=DEFAULT_PREFIX):
    prefix=normalize_prefix(prefix)
    networks=defaultdict(list); invalid=[]
    for asset in assets:
        raw=str(asset.get('ip_address') or '').strip()
        try:
            ip=ipaddress.ip_address(raw)
            if ip.version != 4: raise ValueError('IPv4 only')
            net=str(ipaddress.ip_network(f'{ip}/{prefix}', strict=False))
            row=dict(asset); row['subnet']=net; networks[net].append(row)
        except ValueError:
            row=dict(asset); row['subnet']='Unassigned / Invalid IP'; invalid.append(row)
    summary=[]
    for subnet, rows in sorted(networks.items(), key=lambda x: ipaddress.ip_network(x[0]).network_address):
        groups=Counter(r.get('asset_group','UNKNOWN') for r in rows)
        scans=Counter(r.get('scan_status','Unknown') for r in rows)
        summary.append({'subnet':subnet,'asset_count':len(rows),'groups':dict(groups),'current':scans['Current'],'aging':scans['Aging'],'stale':scans['Stale'],'unknown_scan':scans['Unknown']})
    return {'prefix':prefix,'subnet_count':len(summary),'asset_count':sum(x['asset_count'] for x in summary),'subnets':summary,'subnet_assets':dict(networks),'invalid_assets':invalid}

def _style_sheet(ws):
    ws.freeze_panes='A2'; ws.auto_filter.ref=ws.dimensions
    for cell in ws[1]:
        cell.font=Font(bold=True); cell.fill=PatternFill('solid', fgColor='D9EAF7'); cell.alignment=Alignment(wrap_text=True)
    for col in ws.columns:
        width=min(38,max(11,max(len(str(c.value or '')) for c in col)+2))
        ws.column_dimensions[get_column_letter(col[0].column)].width=width

def build_network_report(assets, prefix=DEFAULT_PREFIX):
    data=build_network_breakdown(assets,prefix)
    wb=Workbook(); ws=wb.active; ws.title='Network Summary'
    ws.append(['Observed Subnet','Unique Assets','Current','Aging','Stale','Unknown Scan','Asset Group Breakdown'])
    for s in data['subnets']:
        breakdown=', '.join(f'{k}: {v}' for k,v in sorted(s['groups'].items()))
        ws.append([s['subnet'],s['asset_count'],s['current'],s['aging'],s['stale'],s['unknown_scan'],breakdown])
    _style_sheet(ws)
    detail=wb.create_sheet('Asset Detail')
    detail.append(['Observed Subnet','Hostname','IP Address','Rapid7 Asset ID','Asset Group','Location','Management','Rapid7 OS','Last Scan','Scan Age (Days)','Scan Status'])
    for subnet in [s['subnet'] for s in data['subnets']]:
        for a in sorted(data['subnet_assets'][subnet],key=lambda x:str(x.get('ip_address',''))):
            detail.append([subnet,a.get('hostname'),a.get('ip_address'),a.get('asset_id'),a.get('asset_group'),a.get('location'),a.get('management'),a.get('operating_system'),a.get('last_scan_timestamp') or a.get('last_scan_date'),a.get('scan_age_days'),a.get('scan_status')])
    for a in data['invalid_assets']:
        detail.append(['Unassigned / Invalid IP',a.get('hostname'),a.get('ip_address'),a.get('asset_id'),a.get('asset_group'),a.get('location'),a.get('management'),a.get('operating_system'),a.get('last_scan_timestamp') or a.get('last_scan_date'),a.get('scan_age_days'),a.get('scan_status')])
    _style_sheet(detail)
    info=wb.create_sheet('Report Information')
    info.append(['Field','Value']); info.append(['Generated',datetime.now().strftime('%Y-%m-%d %H:%M:%S')]); info.append(['Subnet Prefix',f'/{data["prefix"]}']); info.append(['Observed Subnets',data['subnet_count']]); info.append(['Assets with valid IPv4',data['asset_count']]); info.append(['Unassigned / Invalid IP Assets',len(data['invalid_assets'])]); info.append(['Interpretation','Observed Subnets are inferred from asset IP addresses in this Rapid7 export. Presence indicates representation in the export; absence does not prove a subnet was not scanned.'])
    _style_sheet(info)
    out=BytesIO(); wb.save(out); out.seek(0); return out
