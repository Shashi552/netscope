#!/usr/bin/env python3
"""Write the original 180-item planning inventory with honest source status."""
from pathlib import Path
import csv
# S=reachable source, P=partial/narrower source, N=not implemented, C=conditional, R=removed.
items = '''S|Local IP and interface information
P|Suggest connected IPv4 subnet
S|Single IP hostname range and CIDR input
P|Best-effort TCP device discovery
P|Declared-type Bonjour discovery
P|Reverse DNS hostname lookup
S|Explicit or discovered IPv6 target connections
S|Device names tags notes trust labels
P|First-seen last-seen observations
S|Common TCP port quick scan
S|Custom TCP port selection
S|TCP port ranges
S|Full TCP ports 1-65535
S|Multiple authorized hosts
S|Host and port exclusions
S|Concurrency and attempt rate limits
S|Timeout and retries
S|Live discovered open ports
P|Progress and elapsed time
S|Cancel scan
S|Checkpoint and resume unfinished scan
P|Rescan selected devices or ports
P|Reusable scan profiles
S|Distinct connection outcomes
P|Read available service banners
P|Protocol-specific verification
S|Identify HTTP and HTTPS responses
P|Read SSH identification string
P|Read FTP greeting
P|Read SMTP greeting
P|Extract advertised product/version strings
S|Show raw service evidence
S|Separate port hints from confirmed evidence
S|HTTP response status
S|HTTP response headers
S|HTML title extraction
P|Redirect chain observation
S|HTTP duration
S|Advertised server header
P|Security header inspection
S|Observed cleartext HTTP exposure
P|HTTP to HTTPS redirect check
P|Supplied hostname virtual-host SNI testing
S|Presented TLS certificate capture
P|Certificate subject and issuer
S|Certificate validity dates
N|Certificate subject alternative names
S|SHA256 certificate fingerprint
P|Expired or not-yet-valid flag
P|Hostname matching evidence
S|iOS certificate trust evaluation
S|Negotiated TLS/cipher metrics
S|Saved certificate observations
P|Forward hostname resolution
P|DNS record query types
S|Custom resolver UDP or TCP
S|DNS timing and errors
S|TCP connection timing
P|Repeated TCP reachability
P|Active-session reachability changes
S|Local scan history
S|Compare saved scans
P|New device observations
S|Newly observed open ports
S|Previously open now not observed open
N|Changed banner highlighting
P|Changed certificate review
P|Rule-based review observations
P|Evidence timestamps explanations remediation
S|Finding notes accepted risk and labels
P|Finding retest workflow
S|Local certificate expiry reminder
S|Fully graphical workflow
P|Search sort and filters
S|PDF report export
S|CSV and JSON export
S|iOS share sheet
P|Redacted exports
S|Local storage with file protection
S|Keychain app secrets
S|Delete app data and scans
P|Dark mode Dynamic Type VoiceOver
R|Purchases entitlement restore (removed; all free)
S|Pre-scan workload summary
S|Large-scope confirmation
S|Gentle scan profile
N|Per-device scan overrides
N|Automatic concurrency backoff
P|Network-change detection and pause
S|Foreground resume confirmation
P|Live scan statistics
P|Scan completeness summary
P|Local-only target policy
S|Authorization and recorded scope
N|DNS over HTTPS
S|Compare resolver answers
S|DNS TTL display
P|Structured DNS response viewer
P|TCP success rate chart
S|HTTP duration chart
P|Configurable HTTP health checks
C|Unicast Wake-on-LAN
P|Cookie attribute inspection
P|HSTS configuration inspection
P|CSP viewer/explanation
S|Explicit HTTP method requests
P|Response compression inspection
S|Response capture limit indicators
N|HTTP response comparison
S|Non-executing response text preview
S|Redirect scope protection
S|Certificate chain viewer
S|Public-key type and size
N|Public-key fingerprint comparison
N|User-supplied certificate baseline
N|Custom CA trust evaluation
S|Export observed certificate DER
P|Certificate renewal history
P|Import target text/CSV
S|Import own scan JSON
P|Saved device groups
S|Expected-port baselines
P|Baseline deviation reports
P|Custom report branding
S|Report scope and methodology
P|Evidence redaction controls
P|Retention settings
N|Storage usage dashboard
S|Device authentication app lock
S|App-switcher privacy cover
P|Offline help and explanations
P|Permission troubleshooting
S|No automatic scan data upload
N|Sanitized diagnostics export
N|Separate training/demo mode
P|Localization-ready structure
S|Audit projects
P|Client/site workspaces
P|Reusable audit policies
P|Guided assessment workflow
S|Manual assessment checklist
P|Coverage dashboard
N|Finalized immutable assessment snapshots
P|Scope expiration confirmation
S|Service exposure matrix
S|Management service exposure review
S|User-assigned criticality
N|Explainable finding priority calculation
P|Custom exposure rules
N|Related-finding grouping
N|Exception expiry reminders
S|Finding lifecycle
N|Automatic resolution verification
S|API endpoint inspector
P|HTTP request builder
S|HTTPS Basic/Bearer inspection
P|Credential target binding
N|Structured JSON response explorer
P|Response assertions
P|OpenAPI specification import
S|Safe-method default/no automatic imported calls
P|CORS configuration inspection
P|Authentication challenge viewer
N|WebSocket handshake check
P|Executive/technical report views
P|Remediation action plan
P|Before/after remediation report
N|Evidence attachments
S|Evidence file hash manifest
P|Reproducibility details
P|Custom report templates
S|Local activity history
N|Report revision comparison
S|Encrypted audit export/import
P|Sensitive-project mode
P|Per-project retention policy
N|Secret-redaction preview
S|In-app QR target import
N|Saved professional dashboard layouts
P|Custom bounded service probe profiles'''.splitlines()
assert len(items)==180, len(items)
labels={'S':'source','P':'partial','N':'planned','C':'conditional','R':'removed'}
root=Path(__file__).resolve().parents[1]
with (root/'Docs/FEATURE_BACKLOG.csv').open('w',newline='') as f:
    w=csv.writer(f);w.writerow(['Original ID','Feature','Status','Verification','Notes'])
    for i,item in enumerate(items,1):
        status,name=item.split('|',1)
        note={'S':'Code exists; requires Xcode compilation, tests and physical-device verification.', 'P':'Only a narrower workflow exists. See FEATURE_STATUS.md and source; do not advertise full original scope.', 'N':'No working implementation included; do not expose as available.', 'C':'Not implemented. Platform/network feasibility and entitlement review required.', 'R':'User requires everything free; no purchases or monetization.'}[status]
        w.writerow([i,name,labels[status],'NOT DEVICE VERIFIED',note])
print('Wrote 180-item feature backlog')
