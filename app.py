import os, re, json, time, hmac, hashlib, sqlite3, secrets, ipaddress, socket
from datetime import datetime, timezone
from functools import wraps
from urllib.parse import urlparse
import requests
import dns.resolver
from flask import Flask, request, jsonify, render_template, session, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash

APP_NAME = 'CyberLord Domain Intelligence'
DB_PATH = os.getenv('PAYMENTS_DB', 'cyberlord.db')
PRICE_KOBO = 500000
PAYSTACK_SECRET_KEY = os.getenv('PAYSTACK_SECRET_KEY', '')
PAYSTACK_WEBHOOK_SECRET = os.getenv('PAYSTACK_WEBHOOK_SECRET', '')
TON_WALLET_ADDRESS = os.getenv('TON_WALLET_ADDRESS', '')
app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'change-this-before-deployment-' + secrets.token_hex(16))
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Lax', SESSION_COOKIE_SECURE=os.getenv('COOKIE_SECURE', '0') == '1', MAX_CONTENT_LENGTH=1_000_000)


def db():
    conn = sqlite3.connect(DB_PATH, timeout=20)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with db() as c:
        c.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, created_at TEXT NOT NULL)')
        c.execute('CREATE TABLE IF NOT EXISTS payments (reference TEXT PRIMARY KEY, email TEXT NOT NULL, amount INTEGER NOT NULL, currency TEXT NOT NULL, status TEXT NOT NULL, created_at TEXT NOT NULL)')
        c.execute('CREATE TABLE IF NOT EXISTS entitlements (email TEXT PRIMARY KEY, plan TEXT NOT NULL, updated_at TEXT NOT NULL)')
        c.execute('CREATE TABLE IF NOT EXISTS scan_history (id INTEGER PRIMARY KEY, email TEXT NOT NULL, target TEXT NOT NULL, score INTEGER, created_at TEXT NOT NULL, report_json TEXT NOT NULL)')

init_db()


def current_email():
    return session.get('email')


def premium(email=None):
    email = email or current_email()
    if not email:
        return False
    with db() as c:
        return c.execute('SELECT 1 FROM entitlements WHERE email=? AND plan="premium"', (email,)).fetchone() is not None


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
        r = requests.get('https://' + domain, timeout=8, allow_redirects=True, headers=headers, stream=True)
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
    session['email']=email
    return jsonify({'ok':True,'email':email})

@app.post('/api/login')
def login():
    data=request.get_json(silent=True) or {}; email=(data.get('email') or '').strip().lower(); password=data.get('password') or ''
    with db() as c: user=c.execute('SELECT * FROM users WHERE email=?',(email,)).fetchone()
    if not user or not check_password_hash(user['password_hash'],password): return jsonify({'error':'Email or password is incorrect.'}),401
    session['email']=email
    return jsonify({'ok':True,'email':email,'premium':premium(email)})

@app.post('/api/logout')
def logout():
    session.clear(); return jsonify({'ok':True})

@app.get('/api/me')
def me(): return jsonify({'email':current_email(),'premium':premium(),'ton_wallet':TON_WALLET_ADDRESS})

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
    try:
        r=requests.post('https://api.paystack.co/transaction/initialize',headers={'Authorization':'Bearer '+PAYSTACK_SECRET_KEY,'Content-Type':'application/json'},json={'email':email,'amount':PRICE_KOBO,'currency':'NGN','reference':reference,'callback_url':request.url_root.rstrip('/')+'/payment/return','channels':['card','bank','bank_transfer','ussd'],'metadata':{'product':APP_NAME,'plan':'premium'}},timeout=15)
        data=r.json()
        if not data.get('status'): return jsonify({'error':data.get('message','Could not initialize payment.')}),502
        with db() as c: c.execute('INSERT INTO payments(reference,email,amount,currency,status,created_at) VALUES(?,?,?,?,?,?)',(reference,email,PRICE_KOBO,'NGN','pending',datetime.now(timezone.utc).isoformat()))
        return jsonify({'authorization_url':data['data']['authorization_url'],'reference':reference})
    except Exception: return jsonify({'error':'Paystack could not be reached. Try again.'}),502


def verify_reference(reference):
    if not PAYSTACK_SECRET_KEY: return False
    r=requests.get('https://api.paystack.co/transaction/verify/'+reference,headers={'Authorization':'Bearer '+PAYSTACK_SECRET_KEY},timeout=15)
    data=r.json().get('data',{})
    with db() as c: payment=c.execute('SELECT * FROM payments WHERE reference=?',(reference,)).fetchone()
    if not payment: return False
    valid=(data.get('status')=='success' and data.get('amount')==PRICE_KOBO and data.get('currency')=='NGN' and data.get('reference')==reference and (data.get('customer',{}).get('email','').lower()==payment['email'].lower()))
    if valid:
        with db() as c:
            c.execute('UPDATE payments SET status="success" WHERE reference=?',(reference,))
            c.execute('INSERT INTO entitlements(email,plan,updated_at) VALUES(?,?,?) ON CONFLICT(email) DO UPDATE SET plan=excluded.plan,updated_at=excluded.updated_at',(payment['email'],'premium',datetime.now(timezone.utc).isoformat()))
    return valid

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
            if p and data.get('amount')==PRICE_KOBO and data.get('currency')=='NGN' and data.get('customer',{}).get('email','').lower()==p['email'].lower():
                with db() as c:
                    c.execute('UPDATE payments SET status="success" WHERE reference=?',(ref,))
                    c.execute('INSERT INTO entitlements(email,plan,updated_at) VALUES(?,?,?) ON CONFLICT(email) DO UPDATE SET plan=excluded.plan,updated_at=excluded.updated_at',(p['email'],'premium',datetime.now(timezone.utc).isoformat()))
        except Exception: return '',500
    return '',200

@app.errorhandler(429)
def too_many(e): return jsonify({'error':'Too many requests. Please wait and try again.'}),429

if __name__=='__main__': app.run(host='0.0.0.0',port=int(os.getenv('PORT','5000')),debug=False)
