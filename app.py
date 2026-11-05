import os, re, json, time, hmac, hashlib, sqlite3, secrets, ipaddress, socket, base64
from datetime import datetime, timezone, timedelta
from functools import wraps
from urllib.parse import urlparse
import requests
import dns.resolver
from flask import Flask, request, jsonify, render_template, session, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash

APP_NAME = 'CyberLord Domain Intelligence'
DB_PATH = os.getenv('PAYMENTS_DB', 'cyberlord.db')
PRICE_KOBO = 500000  # legacy Premium price; plan-specific prices are resolved server-side
PLAN_PRICES_KOBO = {'premium': int(os.getenv('PREMIUM_PRICE_NGN', '5000')) * 100, 'professional': int(os.getenv('PROFESSIONAL_PRICE_NGN', '10000')) * 100}
PAYSTACK_SECRET_KEY = os.getenv('PAYSTACK_SECRET_KEY', '')
PAYSTACK_WEBHOOK_SECRET = os.getenv('PAYSTACK_WEBHOOK_SECRET', '')
TON_WALLET_ADDRESS = os.getenv('TON_WALLET_ADDRESS', '')
app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'change-this-before-deployment-' + secrets.token_hex(16))
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=os.getenv('COOKIE_SECURE', '0') == '1',
    PERMANENT_SESSION_LIFETIME=timedelta(days=7),
    SESSION_REFRESH_EACH_REQUEST=True,
    MAX_CONTENT_LENGTH=1_000_000
)


def db():
    conn = sqlite3.connect(DB_PATH, timeout=20)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with db() as c:
        c.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, created_at TEXT NOT NULL)')
        c.execute("CREATE TABLE IF NOT EXISTS payments (reference TEXT PRIMARY KEY, email TEXT NOT NULL, amount INTEGER NOT NULL, currency TEXT NOT NULL, status TEXT NOT NULL, created_at TEXT NOT NULL, plan TEXT NOT NULL DEFAULT 'premium')")
        c.execute('CREATE TABLE IF NOT EXISTS entitlements (email TEXT PRIMARY KEY, plan TEXT NOT NULL, updated_at TEXT NOT NULL, expires_at TEXT)')
        # Safe additive migrations for existing installations.
        payment_cols = {r['name'] for r in c.execute('PRAGMA table_info(payments)').fetchall()}
        if 'plan' not in payment_cols: c.execute("ALTER TABLE payments ADD COLUMN plan TEXT NOT NULL DEFAULT 'premium'")
        entitlement_cols = {r['name'] for r in c.execute('PRAGMA table_info(entitlements)').fetchall()}
        if 'expires_at' not in entitlement_cols: c.execute('ALTER TABLE entitlements ADD COLUMN expires_at TEXT')
        # Convert legacy non-expiring paid rows to a 30-day entitlement from their original grant date.
        for old in c.execute('SELECT email, updated_at FROM entitlements WHERE expires_at IS NULL').fetchall():
            try: exp = (datetime.fromisoformat(old['updated_at']) + timedelta(days=30)).isoformat()
            except Exception: exp = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
            c.execute('UPDATE entitlements SET expires_at=? WHERE email=?', (exp, old['email']))
        c.execute('CREATE TABLE IF NOT EXISTS scan_history (id INTEGER PRIMARY KEY, email TEXT NOT NULL, target TEXT NOT NULL, score INTEGER, created_at TEXT NOT NULL, report_json TEXT NOT NULL)')
        c.execute('CREATE TABLE IF NOT EXISTS bybit_payments (merchant_trade_no TEXT PRIMARY KEY, email TEXT NOT NULL, amount TEXT NOT NULL, currency TEXT NOT NULL, status TEXT NOT NULL, pay_id TEXT, created_at TEXT NOT NULL)')

init_db()


def current_email():
    return session.get('email')


def entitlement(email=None):
    email = email or current_email()
    if not email:
        return {'plan': 'free', 'active': False, 'expires_at': None}
    with db() as c:
        row = c.execute('SELECT plan, expires_at FROM entitlements WHERE email=?', (email,)).fetchone()
    if not row:
        return {'plan': 'free', 'active': False, 'expires_at': None}
    expires = row['expires_at']
    active = True
    if expires:
        try: active = datetime.fromisoformat(expires) > datetime.now(timezone.utc)
        except ValueError: active = False
    plan = row['plan'] if active else 'free'
    return {'plan': plan, 'active': plan in ('premium', 'professional'), 'expires_at': expires if active else None}


def premium(email=None):
    return entitlement(email)['active']


def professional(email=None):
    return entitlement(email)['plan'] == 'professional'


def login_required(fn):
    @wraps(fn)
    def wrapped(*a, **kw):
        if not current_email():
            return jsonify({'error': 'Please sign in first.'}), 401
        return fn(*a, **kw)
    return wrapped


def premium_required(fn):
    @wraps(fn)
    def wrapped(*a, **kw):
        if not premium():
            return jsonify({'error': 'Premium feature. Upgrade to unlock this tool.'}), 402
        return fn(*a, **kw)
    return wrapped


def professional_required(fn):
    @wraps(fn)
    def wrapped(*a, **kw):
        if not professional():
            return jsonify({'error': 'Professional feature. Upgrade to the Professional plan to unlock this tool.'}), 402
        return fn(*a, **kw)
    return wrapped


def normalize_domain(value):
    value = (value or '').strip().lower()
    if '://' in value:
        value = urlparse(value).hostname or ''
    value = value.split('/')[0].split(':')[0].strip('.')
    if not value or len(value) > 253 or not re.fullmatch(r'(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}', value):
        raise ValueError('Enter a valid public domain, e.g. example.com')
    return value


def resolve_public(domain):
    try:
        answers = socket.getaddrinfo(domain, None, type=socket.SOCK_STREAM)
        ips = sorted({x[4][0] for x in answers})
    except socket.gaierror:
        raise ValueError('Domain could not be resolved.')
    if not ips:
        raise ValueError('No public IP address found.')
    for ip in ips:
        addr = ipaddress.ip_address(ip)
        if not addr.is_global:
            raise ValueError('Private, local, or reserved network targets are not allowed.')
    return ips


def dns_records(domain):
    result = {}
    for kind in ['A','AAAA','MX','NS','TXT','CAA','SOA']:
        try:
            ans = dns.resolver.resolve(domain, kind, lifetime=4)
            result[kind] = [str(x).strip('"') for x in ans][:30]
        except Exception:
            result[kind] = []
    return result


def tls_info(domain):
    import ssl
    out = {'available': False}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as s:
                cert = s.getpeercert()
                expiry = cert.get('notAfter')
                days = None
                if expiry:
                    dt = datetime.strptime(expiry, '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc)
                    days = (dt - datetime.now(timezone.utc)).days
                out = {'available': True, 'subject': str(cert.get('subject', [])), 'issuer': str(cert.get('issuer', [])), 'expires': expiry, 'days_remaining': days, 'tls_version': s.version(), 'cipher': s.cipher()[0] if s.cipher() else None}
    except Exception as e:
        out['error'] = str(e)[:160]
    return out


def fetch_site(domain):
    headers = {'User-Agent': 'CyberLordDomainIntelligence/1.0 (passive security assessment)'}
    try:
        r = requests.get('https://' + domain, timeout=8, allow_redirects=False, headers=headers, stream=True)
        data = {'status': r.status_code, 'final_url': r.url, 'headers': dict(r.headers), 'cookies': [c.name for c in r.cookies], 'server': r.headers.get('Server'), 'powered_by': r.headers.get('X-Powered-By')}
        r.close()
        return data
    except requests.RequestException as e:
        return {'error': str(e)[:180], 'headers': {}, 'cookies': []}


def score_report(report):
    score = 100
    issues = []
    h = {k.lower(): v for k, v in report.get('http', {}).get('headers', {}).items()}
    checks = [('strict-transport-security','HSTS missing',10),('content-security-policy','Content Security Policy missing',12),('x-content-type-options','X-Content-Type-Options missing',6),('x-frame-options','Clickjacking protection header missing',8),('referrer-policy','Referrer-Policy missing',4),('permissions-policy','Permissions-Policy missing',3)]
    for key, msg, penalty in checks:
        if key not in h:
            score -= penalty; issues.append({'severity':'medium' if penalty < 10 else 'high','finding':msg,'recommendation':f'Configure the {key} response header.'})
    tls = report.get('tls', {})
    if not tls.get('available'):
        score -= 20; issues.append({'severity':'high','finding':'HTTPS/TLS could not be verified','recommendation':'Check the TLS certificate and HTTPS configuration.'})
    elif isinstance(tls.get('days_remaining'), int) and tls['days_remaining'] < 21:
        score -= 15; issues.append({'severity':'high','finding':'TLS certificate expires soon','recommendation':'Renew the certificate before expiry.'})
    dnsr = report.get('dns', {})
    if not dnsr.get('CAA'):
        score -= 3; issues.append({'severity':'low','finding':'No CAA record detected','recommendation':'Consider publishing a CAA record to restrict certificate issuance.'})
    return max(0, min(100, score)), issues


def run_scan(domain):
    ips = resolve_public(domain)
    report = {'domain':domain, 'scanned_at':datetime.now(timezone.utc).isoformat(), 'ips':ips, 'dns':dns_records(domain), 'tls':tls_info(domain), 'http':fetch_site(domain)}
    score, issues = score_report(report)
    report['score'] = score; report['findings'] = issues
    return report


def ct_subdomains(domain, limit=100):
    try:
        r = requests.get('https://crt.sh/', params={'q':'%.'+domain, 'output':'json'}, timeout=12, headers={'User-Agent':'CyberLordDomainIntelligence/1.0'})
        r.raise_for_status()
        names = set()
        for row in r.json():
            for name in row.get('name_value','').splitlines():
                name = name.strip().lower().lstrip('*.')
                if name == domain or name.endswith('.'+domain): names.add(name)
        return sorted(names)[:limit]
    except Exception:
        return []


@app.get('/')
def index():
    return render_template('index.html', email=current_email(), is_premium=premium(), ton_wallet=TON_WALLET_ADDRESS)

@app.post('/api/register')
def register():
    data=request.get_json(silent=True) or {}; email=(data.get('email') or '').strip().lower(); password=data.get('password') or ''
    if not re.fullmatch(r'[^@\s]+@[^@\s]+\.[^@\s]+', email) or len(password)<10:
        return jsonify({'error':'Enter a valid email and a password of at least 10 characters.'}),400
    try:
        with db() as c: c.execute('INSERT INTO users(email,password_hash,created_at) VALUES(?,?,?)',(email,generate_password_hash(password),datetime.now(timezone.utc).isoformat()))
    except sqlite3.IntegrityError: return jsonify({'error':'An account with that email already exists.'}),409
    session.permanent = True
    session['email']=email
    return jsonify({'ok':True,'email':email})

@app.post('/api/login')
def login():
    data=request.get_json(silent=True) or {}; email=(data.get('email') or '').strip().lower(); password=data.get('password') or ''
    with db() as c: user=c.execute('SELECT * FROM users WHERE email=?',(email,)).fetchone()
    if not user or not check_password_hash(user['password_hash'],password): return jsonify({'error':'Email or password is incorrect.'}),401
    session.permanent = True
    session['email']=email
    return jsonify({'ok':True,'email':email,'premium':premium(email)})

@app.post('/api/logout')
def logout():
    session.clear(); return jsonify({'ok':True})

@app.get('/api/me')
def me(): e=entitlement(); return jsonify({'email':current_email(),'premium':e['active'],'plan':e['plan'],'expires_at':e['expires_at'],'professional':e['plan']=='professional','ton_wallet':TON_WALLET_ADDRESS})

@app.post('/api/scan')
@login_required
def scan():
    data=request.get_json(silent=True) or {}
    try: domain=normalize_domain(data.get('domain'))
    except ValueError as e: return jsonify({'error':str(e)}),400
    report=run_scan(domain)
    if not premium():
        report['dns']={k:v for k,v in report['dns'].items() if k in ['A','AAAA','MX','NS']}
        report['findings']=report['findings'][:3]
    with db() as c: c.execute('INSERT INTO scan_history(email,target,score,created_at,report_json) VALUES(?,?,?,?,?)',(current_email(),domain,report['score'],datetime.now(timezone.utc).isoformat(),json.dumps(report)))
    return jsonify(report)

@app.post('/api/subdomains')
@login_required
@premium_required
def subdomains():
    try: domain=normalize_domain((request.get_json(silent=True) or {}).get('domain'))
    except ValueError as e: return jsonify({'error':str(e)}),400
    return jsonify({'domain':domain,'source':'Certificate Transparency (crt.sh)','subdomains':ct_subdomains(domain,500)})

@app.post('/api/email-security')
@login_required
@premium_required
def email_security():
    try: domain=normalize_domain((request.get_json(silent=True) or {}).get('domain'))
    except ValueError as e: return jsonify({'error':str(e)}),400
    result={}
    for label, name in [('SPF',domain),('DMARC','_dmarc.'+domain),('DKIM selector default','default._domainkey.'+domain)]:
        try: result[label]=[str(x).strip('"') for x in dns.resolver.resolve(name,'TXT',lifetime=4)]
        except Exception: result[label]=[]
    return jsonify({'domain':domain,'records':result,'note':'DKIM commonly uses provider-specific selectors; an empty default selector does not prove DKIM is absent.'})

@app.post('/api/ip-intel')
@login_required
@premium_required
def ip_intel():
    raw=(request.get_json(silent=True) or {}).get('ip','').strip()
    try: ip=ipaddress.ip_address(raw)
    except ValueError: return jsonify({'error':'Enter a valid IP address.'}),400
    if not ip.is_global: return jsonify({'error':'Only public IP addresses are supported.'}),400
    try:
        r=requests.get(f'https://ipwho.is/{ip}',timeout=8); data=r.json()
        if not data.get('success',True): return jsonify({'error':'IP intelligence provider returned no result.'}),502
        return jsonify({k:data.get(k) for k in ['ip','type','continent','country','region','city','latitude','longitude','connection','timezone']})
    except Exception: return jsonify({'error':'IP intelligence provider is temporarily unavailable.'}),502

@app.post('/api/cve')
@login_required
@premium_required
def cve_search():
    q=(request.get_json(silent=True) or {}).get('query','').strip()[:100]
    if len(q)<2: return jsonify({'error':'Enter a product, vendor, or CVE identifier.'}),400
    try:
        r=requests.get('https://services.nvd.nist.gov/rest/json/cves/2.0',params={'keywordSearch':q,'resultsPerPage':10},timeout=15)
        r.raise_for_status(); payload=r.json(); items=[]
        for row in payload.get('vulnerabilities',[]):
            c=row.get('cve',{}); metrics=c.get('metrics',{}); score=None; severity='UNKNOWN'
            for metric_key in ['cvssMetricV40','cvssMetricV31','cvssMetricV30','cvssMetricV2']:
                if metrics.get(metric_key):
                    cv=metrics[metric_key][0].get('cvssData',{}); score=cv.get('baseScore'); severity=cv.get('baseSeverity','UNKNOWN'); break
            desc=next((d.get('value') for d in c.get('descriptions',[]) if d.get('lang')=='en'),'')
            items.append({'id':c.get('id'),'published':c.get('published'),'score':score,'severity':severity,'description':desc[:500]})
        return jsonify({'query':q,'results':items,'source':'NIST National Vulnerability Database'})
    except Exception: return jsonify({'error':'NVD is temporarily unavailable. Try again later.'}),502


@app.post('/api/dns-intel')
@login_required
@premium_required
def dns_intel():
    try:
        domain = normalize_domain((request.get_json(silent=True) or {}).get('domain'))
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    records = {}
    for kind in ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CAA', 'SOA']:
        try:
            records[kind] = [str(x).strip('"') for x in dns.resolver.resolve(domain, kind, lifetime=4)][:30]
        except Exception:
            records[kind] = []
    return jsonify({'domain': domain, 'records': records, 'source': 'Public DNS resolver'})


@app.post('/api/technology')
@login_required
@premium_required
def technology_fingerprint():
    try:
        domain = normalize_domain((request.get_json(silent=True) or {}).get('domain'))
        resolve_public(domain)
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    result = fetch_site(domain)
    headers = {str(k).lower(): str(v) for k, v in result.get('headers', {}).items()}
    detected = []
    server = headers.get('server')
    powered = headers.get('x-powered-by')
    if server: detected.append({'category': 'Web server', 'value': server})
    if powered: detected.append({'category': 'Application platform', 'value': powered})
    for key, label in [('x-aspnet-version', 'ASP.NET'), ('x-generator', 'Generator'), ('cf-ray', 'Cloudflare edge'), ('x-vercel-id', 'Vercel'), ('x-amz-cf-id', 'Amazon CloudFront')]:
        if headers.get(key): detected.append({'category': label, 'value': headers[key]})
    detected.append({'category': 'HTTPS', 'value': 'Available' if result.get('status') else 'Not confirmed'})
    return jsonify({'domain': domain, 'technologies': detected, 'http_status': result.get('status'), 'note': 'Passive fingerprinting only. Some technologies intentionally hide identifying headers.'})


@app.post('/api/port-scan')
@login_required
@premium_required
def limited_port_scan():
    data = request.get_json(silent=True) or {}
    try:
        domain = normalize_domain(data.get('domain'))
        ips = resolve_public(domain)
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    # Restrained connect checks against common TCP service ports only.
    ports = [22, 25, 53, 80, 110, 143, 443, 445, 587, 993, 995, 3306, 3389, 5432, 8080, 8443]
    ip = ips[0]
    found = []
    for port in ports:
        try:
            with socket.create_connection((ip, port), timeout=0.45):
                found.append({'port': port, 'state': 'open'})
        except (OSError, TimeoutError):
            pass
    return jsonify({'domain': domain, 'ip_checked': ip, 'ports_checked': len(ports), 'open_ports': found,
                    'note': 'Limited TCP connect checks only. Run only against systems you own or are explicitly authorised to assess.'})


@app.post('/api/compare')
@login_required
@premium_required
def compare():
    data=request.get_json(silent=True) or {}
    try: a=normalize_domain(data.get('domain_a')); b=normalize_domain(data.get('domain_b'))
    except ValueError as e: return jsonify({'error':str(e)}),400
    if a==b: return jsonify({'error':'Enter two different domains.'}),400
    ra=run_scan(a); rb=run_scan(b)
    return jsonify({'domain_a':{'domain':a,'score':ra['score'],'ips':ra['ips'],'tls':ra['tls'],'findings':ra['findings']},'domain_b':{'domain':b,'score':rb['score'],'ips':rb['ips'],'tls':rb['tls'],'findings':rb['findings']}})

@app.post('/api/email-intel')
@login_required
@premium_required
def individual_email_intel():
    raw = (request.get_json(silent=True) or {}).get('email', '').strip().lower()
    if len(raw) > 254 or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", raw):
        return jsonify({'error': 'Enter one valid individual email address.'}), 400
    local, domain = raw.rsplit('@', 1)
    try: domain = normalize_domain(domain)
    except ValueError as e: return jsonify({'error': 'The email domain is not valid: ' + str(e)}), 400
    records = {}
    for kind in ['MX', 'TXT']:
        try: records[kind] = [str(x).strip('"') for x in dns.resolver.resolve(domain, kind, lifetime=4)][:30]
        except Exception: records[kind] = []
    try:
        dmarc = [str(x).strip('"') for x in dns.resolver.resolve('_dmarc.' + domain, 'TXT', lifetime=4)]
    except Exception: dmarc = []
    txt = records.get('TXT', [])
    return jsonify({'email': raw, 'local_part_present': bool(local), 'domain': domain,
                    'mx_records': records['MX'], 'spf_records': [x for x in txt if x.lower().startswith('v=spf1')],
                    'dmarc_records': dmarc, 'has_mx': bool(records['MX']),
                    'note': 'This checks public mail-domain configuration only. It does not confirm mailbox existence, ownership, inbox access, or breach status.'})


@app.post('/api/breach-check')
@login_required
@premium_required
def breach_check():
    """Return breach-notification metadata only; never fetch passwords or private content."""
    address = (request.get_json(silent=True) or {}).get('email', '').strip().lower()
    if len(address) > 254 or not re.fullmatch(r'[^@\s]+@[^@\s]+\.[^@\s]+', address):
        return jsonify({'error': 'Enter one valid email address.'}), 400
    api_key = os.getenv('HIBP_API_KEY', '')
    if not api_key:
        return jsonify({'error': 'Breach checking is not configured. Add HIBP_API_KEY in the hosting environment.'}), 503
    try:
        response = requests.get(
            'https://haveibeenpwned.com/api/v3/breachedaccount/' + requests.utils.quote(address, safe=''),
            headers={'hibp-api-key': api_key, 'user-agent': 'CyberLord-Domain-Intelligence'},
            params={'truncateResponse': 'true'}, timeout=15)
        if response.status_code == 404:
            return jsonify({'email': address, 'found': False, 'breaches': [], 'breach_count': 0,
                'source': 'Have I Been Pwned', 'checked_at': datetime.now(timezone.utc).isoformat(),
                'note': 'No matching breach was returned by this source. This is not proof the account was never exposed.'})
        if response.status_code == 401:
            return jsonify({'error': 'The breach intelligence API key was rejected.'}), 502
        response.raise_for_status()
        rows = response.json() if response.content else []
        breaches = [{'name': x.get('Name'), 'title': x.get('Title'), 'domain': x.get('Domain'),
            'breach_date': x.get('BreachDate'), 'added_date': x.get('AddedDate'),
            'data_classes': x.get('DataClasses', []), 'verified': x.get('IsVerified', False)} for x in rows]
        return jsonify({'email': address, 'found': bool(breaches), 'breach_count': len(breaches),
            'breaches': breaches, 'source': 'Have I Been Pwned',
            'checked_at': datetime.now(timezone.utc).isoformat(),
            'note': 'Breach metadata only. Passwords, private messages, and raw leaked records are never retrieved or displayed.'})
    except requests.RequestException:
        return jsonify({'error': 'The breach intelligence provider is temporarily unavailable.'}), 502


@app.post('/api/phone-intel')
@login_required
@premium_required
def phone_intel():
    raw = (request.get_json(silent=True) or {}).get('phone', '').strip()
    if not raw or len(raw) > 40:
        return jsonify({'error': 'Enter a phone number including its country code, e.g. +2348012345678.'}), 400
    try:
        import phonenumbers
        from phonenumbers import carrier, geocoder, number_type
        number = phonenumbers.parse(raw, None)
        if not phonenumbers.is_possible_number(number) or not phonenumbers.is_valid_number(number):
            return jsonify({'error': 'The number does not appear to be a valid number in its numbering region.'}), 400
        kinds = {0:'FIXED_LINE',1:'MOBILE',2:'FIXED_LINE_OR_MOBILE',3:'TOLL_FREE',4:'PREMIUM_RATE',5:'SHARED_COST',6:'VOIP',7:'PERSONAL_NUMBER',8:'PAGER',9:'UAN',10:'VOICEMAIL',99:'UNKNOWN'}
        return jsonify({'input': raw, 'international_format': phonenumbers.format_number(number, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
                        'e164': phonenumbers.format_number(number, phonenumbers.PhoneNumberFormat.E164),
                        'valid_numbering_plan': True, 'country_code': number.country_code,
                        'region': phonenumbers.region_code_for_number(number),
                        'location': geocoder.description_for_number(number, 'en'),
                        'number_type': kinds.get(number_type(number), 'UNKNOWN'),
                        'carrier': carrier.name_for_number(number, 'en') or 'Not available',
                        'ownership_verified': False,
                        'note': 'Numbering-plan and public metadata only. This does not prove that the user owns or controls the number. SMS OTP ownership verification requires a configured SMS provider.'})
    except ImportError:
        return jsonify({'error': 'Phone intelligence dependency is not installed. Deploy the updated requirements.txt.'}), 503
    except Exception:
        return jsonify({'error': 'Use international format with a +country code, for example +2348012345678.'}), 400


@app.post('/api/attack-surface-map')
@login_required
@professional_required
def attack_surface_map():
    try: domain = normalize_domain((request.get_json(silent=True) or {}).get('domain'))
    except ValueError as e: return jsonify({'error': str(e)}), 400
    ips = resolve_public(domain)
    subs = ct_subdomains(domain, 250)
    records = dns_records(domain)
    return jsonify({'domain': domain, 'public_ips': ips, 'subdomains': subs, 'dns': records,
                    'tls': tls_info(domain), 'mapping_scope': 'Passive public DNS and certificate-transparency data only',
                    'note': 'This map does not exploit hosts or probe third-party infrastructure. Assess only assets you own or are authorised to test.'})


@app.get('/api/history')
@login_required
def history():
    with db() as c: rows=c.execute('SELECT id,target,score,created_at FROM scan_history WHERE email=? ORDER BY id DESC LIMIT 50',(current_email(),)).fetchall()
    return jsonify([dict(x) for x in rows])

@app.get('/api/report/<int:report_id>')
@login_required
@premium_required
def report(report_id):
    with db() as c: row=c.execute('SELECT report_json FROM scan_history WHERE id=? AND email=?',(report_id,current_email())).fetchone()
    if not row: return jsonify({'error':'Report not found.'}),404
    return app.response_class(row['report_json'],mimetype='application/json',headers={'Content-Disposition':f'attachment; filename=cyberlord-report-{report_id}.json'})

@app.post('/api/payment/initialize')
@login_required
def payment_initialize():
    if not PAYSTACK_SECRET_KEY: return jsonify({'error':'Payments are not configured yet. Add PAYSTACK_SECRET_KEY in your hosting environment.'}),503
    email=current_email(); reference='CLDI_'+secrets.token_hex(12)
    plan = (request.get_json(silent=True) or {}).get('plan', 'premium')
    if plan not in PLAN_PRICES_KOBO: return jsonify({'error':'Choose a valid paid plan.'}),400
    amount_kobo = PLAN_PRICES_KOBO[plan]
    try:
        r=requests.post('https://api.paystack.co/transaction/initialize',headers={'Authorization':'Bearer '+PAYSTACK_SECRET_KEY,'Content-Type':'application/json'},json={'email':email,'amount':amount_kobo,'currency':'NGN','reference':reference,'callback_url':request.url_root.rstrip('/')+'/payment/return','channels':['card','bank','bank_transfer','ussd'],'metadata':{'product':APP_NAME,'plan':plan}},timeout=15)
        data=r.json()
        if not data.get('status'): return jsonify({'error':data.get('message','Could not initialize payment.')}),502
        with db() as c: c.execute('INSERT INTO payments(reference,email,amount,currency,status,created_at,plan) VALUES(?,?,?,?,?,?,?)',(reference,email,amount_kobo,'NGN','pending',datetime.now(timezone.utc).isoformat(),plan))
        return jsonify({'authorization_url':data['data']['authorization_url'],'reference':reference})
    except Exception: return jsonify({'error':'Paystack could not be reached. Try again.'}),502


def verify_reference(reference):
    if not PAYSTACK_SECRET_KEY: return False
    r=requests.get('https://api.paystack.co/transaction/verify/'+reference,headers={'Authorization':'Bearer '+PAYSTACK_SECRET_KEY},timeout=15)
    data=r.json().get('data',{})
    with db() as c: payment=c.execute('SELECT * FROM payments WHERE reference=?',(reference,)).fetchone()
    if not payment: return False
    if payment['status'] == 'success': return True
    valid=(data.get('status')=='success' and data.get('amount')==payment['amount'] and data.get('amount')==PLAN_PRICES_KOBO.get(payment['plan']) and data.get('currency')=='NGN' and data.get('reference')==reference and (data.get('customer',{}).get('email','').lower()==payment['email'].lower()))
    if valid:
        with db() as c:
            c.execute('UPDATE payments SET status="success" WHERE reference=?',(reference,))
            expires=(datetime.now(timezone.utc)+timedelta(days=30)).isoformat()
            c.execute('INSERT INTO entitlements(email,plan,updated_at,expires_at) VALUES(?,?,?,?) ON CONFLICT(email) DO UPDATE SET plan=excluded.plan,updated_at=excluded.updated_at,expires_at=excluded.expires_at',(payment['email'],payment['plan'],datetime.now(timezone.utc).isoformat(),expires))
    return valid


def bybit_pay_configured():
    return all(os.getenv(k) for k in ['BYBIT_PAY_API_KEY', 'BYBIT_PAY_API_SECRET', 'BYBIT_MERCHANT_ID',
                                      'BYBIT_PREMIUM_PRICE_USDT', 'BYBIT_PAY_PLATFORM_PUBLIC_KEY'])


@app.post('/api/bybit/initialize')
@login_required
def bybit_initialize():
    required = ['BYBIT_PAY_API_KEY', 'BYBIT_PAY_API_SECRET', 'BYBIT_MERCHANT_ID', 'BYBIT_PREMIUM_PRICE_USDT', 'BYBIT_PAY_PLATFORM_PUBLIC_KEY']
    missing = [k for k in required if not os.getenv(k)]
    if missing:
        return jsonify({'error': 'Bybit Pay merchant integration is not configured. It requires an approved Bybit Pay merchant account and the server environment variables: ' + ', '.join(missing)}), 503
    try:
        amount = f"{float(os.environ['BYBIT_PREMIUM_PRICE_USDT']):.2f}"
        if float(amount) <= 0:
            raise ValueError()
    except ValueError:
        return jsonify({'error': 'BYBIT_PREMIUM_PRICE_USDT must be a positive amount.'}), 503

    email = current_email()
    trade_no = 'CLDI_' + secrets.token_hex(12)
    now_ms = str(int(time.time() * 1000))
    recv_window = '5000'
    base_url = os.getenv('BYBIT_PAY_BASE_URL', 'https://api2.bybit.com').rstrip('/')
    origin = request.url_root.rstrip('/')
    payload = {
        'merchantId': os.environ['BYBIT_MERCHANT_ID'],
        'merchantName': os.getenv('BYBIT_MERCHANT_NAME', 'CyberLord Domain Intelligence'),
        'paymentType': 'E_COMMERCE',
        'merchantTradeNo': trade_no,
        'orderAmount': amount,
        'currency': 'USDT',
        'currencyType': 'crypto',
        'successUrl': origin + '/payment/bybit/return',
        'failedUrl': origin + '/payment/bybit/return?status=failed',
        'webhookUrl': origin + '/api/bybit/webhook',
        'orderExpireTime': int(time.time()) + 3600,
        'goods': [{
            'shoppingName': 'CyberLord Domain Intelligence',
            'mccCode': '5816',
            'goodsName': 'CyberLord Premium Access',
            'goodsDetail': 'Premium access to defensive domain intelligence tools'
        }],
        'customer': {'externalUserId': email},
        'env': {
            'terminalType': 'WEB',
            'device': (request.headers.get('User-Agent', 'Web browser')[:180]),
            'browserVersion': (request.headers.get('User-Agent', 'Unknown')[:180]),
            'ip': request.remote_addr or '0.0.0.0'
        }
    }
    body = json.dumps(payload, separators=(',', ':'), ensure_ascii=False)
    api_key = os.environ['BYBIT_PAY_API_KEY']
    secret = os.environ['BYBIT_PAY_API_SECRET']
    sign_payload = now_ms + api_key + recv_window + body
    signature = hmac.new(secret.encode(), sign_payload.encode(), hashlib.sha256).hexdigest()
    headers = {
        'X-BAPI-API-KEY': api_key,
        'X-BAPI-TIMESTAMP': now_ms,
        'X-BAPI-RECV-WINDOW': recv_window,
        'X-BAPI-SIGN': signature,
        'Content-Type': 'application/json'
    }
    try:
        response = requests.post(base_url + '/v5/bybitpay/create_pay', data=body.encode('utf-8'), headers=headers, timeout=20)
        response.raise_for_status()
        data = response.json()
        if data.get('retCode') != 100000:
            return jsonify({'error': 'Bybit Pay rejected the checkout request: ' + str(data.get('retMsg', 'Unknown error'))[:180]}), 502
        result = data.get('result') or {}
        checkout = result.get('checkoutLink') or result.get('payUrl')
        if not checkout:
            return jsonify({'error': 'Bybit did not return a checkout link. Check your merchant configuration.'}), 502
        with db() as c:
            c.execute('INSERT INTO bybit_payments(merchant_trade_no,email,amount,currency,status,pay_id,created_at) VALUES(?,?,?,?,?,?,?)',
                      (trade_no, email, amount, 'USDT', 'pending', result.get('payId'), datetime.now(timezone.utc).isoformat()))
        return jsonify({'checkout_url': checkout, 'qr_content': result.get('qrContent'), 'merchant_trade_no': trade_no, 'amount': amount, 'currency': 'USDT'})
    except requests.RequestException:
        return jsonify({'error': 'Could not connect to Bybit Pay. Try again later.'}), 502
    except Exception:
        return jsonify({'error': 'Bybit Pay checkout could not be created. Check server configuration.'}), 502


@app.post('/api/bybit/webhook')
def bybit_webhook():
    public_pem = os.getenv('BYBIT_PAY_PLATFORM_PUBLIC_KEY', '')
    timestamp = request.headers.get('timestamp', '')
    signature = request.headers.get('signature', '')
    raw = request.get_data(cache=False)
    if not public_pem or not timestamp or not signature:
        return 'Webhook verification is not configured', 503
    try:
        ts = int(timestamp)
        if abs(int(time.time()) - ts) > 300:
            return 'Stale webhook', 401
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding
        public_key = serialization.load_pem_public_key(public_pem.replace(r'\\n', '\n').encode())
        public_key.verify(base64.b64decode(signature), timestamp.encode() + raw, padding.PKCS1v15(), hashes.SHA256())
        event = json.loads(raw.decode('utf-8'))
    except Exception:
        return 'Invalid webhook signature', 401

    if event.get('merchantId') != os.getenv('BYBIT_MERCHANT_ID'):
        return 'Merchant mismatch', 400
    trade_no = event.get('merchantTradeNo', '')
    if event.get('status') == 'PAY_SUCCESS' and event.get('paymentType') == 'E_COMMERCE':
        with db() as c:
            payment = c.execute('SELECT * FROM bybit_payments WHERE merchant_trade_no=?', (trade_no,)).fetchone()
        if payment and payment['status'] != 'success' and event.get('currency') == 'USDT' and str(event.get('amount')) == payment['amount']:
            with db() as c:
                c.execute('UPDATE bybit_payments SET status="success", pay_id=COALESCE(?,pay_id) WHERE merchant_trade_no=?',
                          (event.get('payId'), trade_no))
                expires=(datetime.now(timezone.utc)+timedelta(days=30)).isoformat()
                c.execute('INSERT INTO entitlements(email,plan,updated_at,expires_at) VALUES(?,?,?,?) ON CONFLICT(email) DO UPDATE SET plan=excluded.plan,updated_at=excluded.updated_at,expires_at=excluded.expires_at',
                          (payment['email'], 'premium', datetime.now(timezone.utc).isoformat(), expires))
    return 'success', 200


@app.get('/payment/bybit/return')
def bybit_payment_return():
    return render_template('payment_result.html', success=False, provider='Bybit Pay',
                           message='Your payment is being confirmed. Premium access activates automatically after Bybit verifies the payment and sends its signed notification.')


@app.get('/payment/return')
def payment_return():
    ref=request.args.get('reference') or request.args.get('trxref')
    try: ok=verify_reference(ref) if ref else False
    except Exception: ok=False
    return render_template('payment_result.html',success=ok)

@app.post('/api/paystack/webhook')
def paystack_webhook():
    raw=request.get_data(); signature=request.headers.get('x-paystack-signature','')
    # Paystack's standard webhook signature is HMAC-SHA512 using the secret key.
    if not PAYSTACK_SECRET_KEY: return '',503
    expected=hmac.new(PAYSTACK_SECRET_KEY.encode(),raw,hashlib.sha512).hexdigest()
    if not hmac.compare_digest(expected,signature): return '',401
    event=request.get_json(silent=True) or {}; data=event.get('data',{})
    if event.get('event')=='charge.success':
        ref=data.get('reference','')
        try:
            with db() as c: p=c.execute('SELECT * FROM payments WHERE reference=?',(ref,)).fetchone()
            if p and p['status'] != 'success' and data.get('reference')==ref and data.get('amount')==p['amount'] and data.get('amount')==PLAN_PRICES_KOBO.get(p['plan']) and data.get('currency')=='NGN' and data.get('customer',{}).get('email','').lower()==p['email'].lower():
                with db() as c:
                    c.execute('UPDATE payments SET status="success" WHERE reference=?',(ref,))
                    expires=(datetime.now(timezone.utc)+timedelta(days=30)).isoformat()
                    c.execute('INSERT INTO entitlements(email,plan,updated_at,expires_at) VALUES(?,?,?,?) ON CONFLICT(email) DO UPDATE SET plan=excluded.plan,updated_at=excluded.updated_at,expires_at=excluded.expires_at',(p['email'],p['plan'],datetime.now(timezone.utc).isoformat(),expires))
        except Exception: return '',500
    return '',200

@app.errorhandler(429)
def too_many(e): return jsonify({'error':'Too many requests. Please wait and try again.'}),429

if __name__=='__main__': app.run(host='0.0.0.0',port=int(os.getenv('PORT','5000')),debug=False)
