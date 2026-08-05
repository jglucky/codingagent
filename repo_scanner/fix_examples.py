"""Before/after code examples for security findings."""

from __future__ import annotations

from dataclasses import dataclass

from .models import Finding


@dataclass(frozen=True)
class FixExample:
    before: str
    after: str
    language: str = "text"
    note: str = ""


# Rule-id prefix / exact-id → multi-language examples (first match wins by specificity)
_EXAMPLES: dict[str, dict[str, FixExample]] = {
    "policy-1/password-assignment": {
        "py": FixExample(
            before='password = "SuperSecret123!"',
            after='import os\npassword = os.environ["DB_PASSWORD"]  # inject from vault/CI secrets',
            language="python",
            note="Never hardcode passwords; load from environment or a secrets manager.",
        ),
        "cs": FixExample(
            before='string password = "SuperSecret123!";',
            after='// Prefer Azure Key Vault / user-secrets / env vars\nvar password = Environment.GetEnvironmentVariable("DB_PASSWORD");',
            language="csharp",
        ),
        "js": FixExample(
            before='const password = "SuperSecret123!";',
            after='const password = process.env.DB_PASSWORD;',
            language="javascript",
        ),
        "*": FixExample(
            before='password = "hardcoded-secret"',
            after='password = getenv("DB_PASSWORD")  // or vault SDK',
            language="text",
        ),
    },
    "policy-1/password-in-object": {
        "*": FixExample(
            before='{ "password": "hardcoded-secret" }',
            after='{ "password": "${DB_PASSWORD}" }  // resolve at runtime from env/vault',
            language="json",
        ),
    },
    "policy-1/password-in-connection": {
        "py": FixExample(
            before='conn = "Server=db;Password=SuperSecret;"',
            after='conn = os.environ["DATABASE_URL"]  # vault-backed connection string',
            language="python",
        ),
        "cs": FixExample(
            before='"Server=.;Database=app;Password=SuperSecret;"',
            after='builder.Configuration.GetConnectionString("Default")\n// store secret outside source (Key Vault / user-secrets)',
            language="csharp",
        ),
        "*": FixExample(
            before="Password=SuperSecret;",
            after="Password=<from-secrets-manager>;",
            language="text",
        ),
    },
    "policy-2/": {
        "py": FixExample(
            before='API_KEY = "sk_live_abc123..."',
            after='API_KEY = os.environ["API_KEY"]',
            language="python",
        ),
        "js": FixExample(
            before='const apiKey = "sk_live_abc123...";',
            after='const apiKey = process.env.API_KEY;',
            language="javascript",
        ),
        "cs": FixExample(
            before='var apiKey = "sk_live_abc123...";',
            after='var apiKey = configuration["ApiKey"]; // from Key Vault / env',
            language="csharp",
        ),
        "*": FixExample(
            before='api_key = "sk_live_..."',
            after='api_key = getenv("API_KEY")',
            language="text",
        ),
    },
    "policy-3/": {
        "*": FixExample(
            before='client_secret = "oauth-secret-value"',
            after='client_secret = getenv("OAUTH_CLIENT_SECRET")',
            language="text",
        ),
    },
    "policy-4/": {
        "*": FixExample(
            before='AWS_SECRET_ACCESS_KEY = "wJalrXUtn..."',
            after='# Use IAM roles / instance profiles / workload identity\n# Do not commit cloud keys',
            language="text",
        ),
    },
    "policy-5/": {
        "*": FixExample(
            before="-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----",
            after="# Store keys in a vault / KMS / platform cert store\n# Reference by name at deploy time",
            language="text",
        ),
    },
    "policy-6/": {
        "*": FixExample(
            before="API_KEY=sk_live_committed_in_dotenv",
            after="# .env is gitignored; inject secrets in CI/CD or a vault\nAPI_KEY=${API_KEY}",
            language="bash",
        ),
    },
    "policy-7/": {
        "*": FixExample(
            before='password: "config-secret"',
            after='password: ${DB_PASSWORD}  # or vault reference',
            language="yaml",
        ),
    },
    "policy-8/": {
        "*": FixExample(
            before="# secrets loaded from source / committed files",
            after="# Integrate a secrets manager, e.g.:\n# - HashiCorp Vault / AWS Secrets Manager\n# - Azure Key Vault / GCP Secret Manager",
            language="text",
            note="Implement a vault when the app handles secrets.",
        ),
    },
    "injection/sql": {
        "py": FixExample(
            before='db.execute(f"SELECT * FROM users WHERE id = \'{user_id}\'")',
            after='db.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
            language="python",
        ),
        "js": FixExample(
            before='db.query("SELECT * FROM users WHERE id = \'" + userId + "\'")',
            after='db.query("SELECT * FROM users WHERE id = ?", [userId])',
            language="javascript",
        ),
        "cs": FixExample(
            before='var sql = "SELECT * FROM users WHERE id = " + userId;\nnew SqlCommand(sql, conn);',
            after='var cmd = new SqlCommand("SELECT * FROM users WHERE id = @id", conn);\ncmd.Parameters.AddWithValue("@id", userId);',
            language="csharp",
        ),
        "*": FixExample(
            before='query = "SELECT * FROM t WHERE id = " + userInput',
            after="query = parameterized statement with bound parameters",
            language="text",
        ),
    },
    "injection/csharp-sql": {
        "cs": FixExample(
            before='new SqlCommand("SELECT * FROM t WHERE id = " + id, conn);',
            after='var cmd = new SqlCommand("SELECT * FROM t WHERE id = @id", conn);\ncmd.Parameters.AddWithValue("@id", id);',
            language="csharp",
        ),
    },
    "injection/command": {
        "py": FixExample(
            before="os.system(user_cmd)\nsubprocess.run(user_cmd, shell=True)",
            after='subprocess.run(["/usr/bin/tool", arg], shell=False, check=True)',
            language="python",
        ),
        "js": FixExample(
            before="child_process.exec(userInput)",
            after='child_process.execFile("tool", [safeArg], callback)',
            language="javascript",
        ),
        "*": FixExample(
            before="shell.execute(user_input)",
            after="use argument list APIs; never pass raw user input to a shell",
            language="text",
        ),
    },
    "injection/shell-true": {
        "py": FixExample(
            before="subprocess.run(cmd, shell=True)",
            after='subprocess.run(["cmd", "arg1", "arg2"], shell=False)',
            language="python",
        ),
    },
    "injection/csharp-process": {
        "cs": FixExample(
            before='Process.Start("cmd.exe", "/c " + userInput);',
            after='var psi = new ProcessStartInfo\n{\n  FileName = "tool.exe",\n  ArgumentList = { validatedArg },\n  UseShellExecute = false,\n};\nProcess.Start(psi);',
            language="csharp",
        ),
    },
    "injection/nosql": {
        "js": FixExample(
            before="db.users.find(req.body)",
            after="db.users.find({ email: String(req.body.email) })  // map fields; block $ operators",
            language="javascript",
        ),
        "*": FixExample(
            before="collection.find(request_json)",
            after="collection.find({ field: validated_value })",
            language="text",
        ),
    },
    "xss/inner-html": {
        "js": FixExample(
            before="element.innerHTML = userInput;",
            after="element.textContent = userInput;\n// or: element.innerHTML = DOMPurify.sanitize(userInput);",
            language="javascript",
        ),
    },
    "xss/razor-raw": {
        "cs": FixExample(
            before="@Html.Raw(Model.UserContent)",
            after="@Model.UserContent  // Razor encodes by default\n// If HTML is required: sanitize first, then Html.Raw",
            language="csharp",
        ),
    },
    "iv-5/": {
        "js": FixExample(
            before="el.innerHTML = req.body.comment;",
            after="el.textContent = req.body.comment;\n// or sanitize with DOMPurify",
            language="javascript",
        ),
        "py": FixExample(
            before="return render_template_string(user_html)",
            after="return render_template('safe.html', text=escape(user_text))",
            language="python",
        ),
        "*": FixExample(
            before="render(user_controlled_html)",
            after="encode/escape output; sanitize HTML with a trusted library",
            language="text",
        ),
    },
    "traversal/": {
        "py": FixExample(
            before="open(request.args['file']).read()",
            after='base = Path("/var/data").resolve()\ntarget = (base / filename).resolve()\nif not str(target).startswith(str(base)):\n    raise ValueError("path escape")\ntarget.read_text()',
            language="python",
        ),
        "cs": FixExample(
            before="File.ReadAllText(Request.Query[\"path\"]);",
            after='var baseDir = Path.GetFullPath(contentRoot);\nvar full = Path.GetFullPath(Path.Combine(baseDir, fileName));\nif (!full.StartsWith(baseDir)) throw new UnauthorizedAccessException();\nreturn System.IO.File.ReadAllText(full);',
            language="csharp",
        ),
        "js": FixExample(
            before="fs.readFileSync(req.query.file)",
            after='const full = path.resolve(BASE, req.query.file);\nif (!full.startsWith(BASE)) throw new Error("denied");\nfs.readFileSync(full);',
            language="javascript",
        ),
    },
    "deser/pickle": {
        "py": FixExample(
            before="data = pickle.loads(untrusted)",
            after="data = json.loads(untrusted)  # never unpickle untrusted data",
            language="python",
        ),
    },
    "deser/yaml-unsafe": {
        "py": FixExample(
            before="yaml.load(stream)",
            after="yaml.safe_load(stream)",
            language="python",
        ),
    },
    "deser/binary-formatter": {
        "cs": FixExample(
            before="var bf = new BinaryFormatter();\nvar obj = bf.Deserialize(stream);",
            after="// Prefer System.Text.Json\nvar obj = JsonSerializer.Deserialize<MyType>(utf8Json);",
            language="csharp",
        ),
    },
    "crypto/weak-hash": {
        "py": FixExample(
            before="hashlib.md5(password.encode()).hexdigest()",
            after="import bcrypt\nhashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())",
            language="python",
        ),
        "cs": FixExample(
            before="MD5.Create().ComputeHash(bytes);",
            after="// Passwords: use ASP.NET Identity PasswordHasher / PBKDF2 / Argon2\n// Integrity: SHA256.Create()",
            language="csharp",
        ),
        "*": FixExample(
            before="md5(data) / sha1(data)",
            after="SHA-256+ for integrity; bcrypt/scrypt/Argon2 for passwords",
            language="text",
        ),
    },
    "crypto/hardcoded-iv": {
        "*": FixExample(
            before='iv = "0123456789abcdef"\nencryption_key = "fixed-key-value"',
            after="iv = os.urandom(16)  # unique per message\nkey = load_from_kms_or_vault()",
            language="python",
        ),
    },
    "security/ssl-verify": {
        "py": FixExample(
            before="requests.get(url, verify=False)",
            after="requests.get(url, verify=True)  # fix the certificate instead",
            language="python",
        ),
        "js": FixExample(
            before="process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'",
            after="// Remove override; use valid certificates / proper CA bundle",
            language="javascript",
        ),
        "cs": FixExample(
            before="ServerCertificateCustomValidationCallback = ... always true",
            after="// Use default certificate validation; fix cert chain issues",
            language="csharp",
        ),
    },
    "security/debug": {
        "py": FixExample(
            before="app.run(debug=True)\nDEBUG = True",
            after="DEBUG = False  # production\n# app.run(debug=False)",
            language="python",
        ),
        "cs": FixExample(
            before="app.UseDeveloperExceptionPage();",
            after='if (app.Environment.IsDevelopment())\n    app.UseDeveloperExceptionPage();\nelse\n    app.UseExceptionHandler("/error");',
            language="csharp",
        ),
        "*": FixExample(
            before="debug: true",
            after="debug: false  # production",
            language="yaml",
        ),
    },
    "security/cors": {
        "*": FixExample(
            before='Access-Control-Allow-Origin: *\ncors({ origin: "*" })',
            after='Access-Control-Allow-Origin: https://app.example.com\ncors({ origin: ["https://app.example.com"] })',
            language="text",
        ),
    },
    "security/csrf": {
        "py": FixExample(
            before="@csrf_exempt\ndef transfer(request): ...",
            after="# Remove csrf_exempt; ensure CSRF middleware + tokens on state-changing views",
            language="python",
        ),
        "cs": FixExample(
            before="[IgnoreAntiforgeryToken]\npublic IActionResult Post() { ... }",
            after="[ValidateAntiForgeryToken]\npublic IActionResult Post() { ... }",
            language="csharp",
        ),
        "js": FixExample(
            before="csrfProtection: false",
            after="app.use(csrf());  // enable anti-CSRF tokens for state changes",
            language="javascript",
        ),
    },
    "security/ssrf": {
        "py": FixExample(
            before="requests.get(request.args['url'])",
            after="url = request.args['url']\nif not is_allowed_url(url):  # allowlist host + block private IPs\n    abort(400)\nrequests.get(url, timeout=5)",
            language="python",
        ),
        "cs": FixExample(
            before="await httpClient.GetAsync(Request.Query[\"url\"]);",
            after="// Validate URL against allowlist; block link-local/private ranges\nawait httpClient.GetAsync(validatedUrl);",
            language="csharp",
        ),
    },
    "security/weak-random": {
        "py": FixExample(
            before="token = random.randint(0, 999999)",
            after="import secrets\ntoken = secrets.token_urlsafe(32)",
            language="python",
        ),
        "js": FixExample(
            before="const token = Math.random().toString(36);",
            after="const token = crypto.randomBytes(32).toString('hex');",
            language="javascript",
        ),
        "cs": FixExample(
            before="var n = new Random().Next();",
            after="var bytes = RandomNumberGenerator.GetBytes(32);",
            language="csharp",
        ),
    },
    "security/log-sensitive": {
        "py": FixExample(
            before='logger.info("login password=%s", password)',
            after='logger.info("login user=%s", username)  # never log secrets',
            language="python",
        ),
        "cs": FixExample(
            before='_logger.LogInformation("token={Token}", token);',
            after='_logger.LogInformation("auth succeeded for {User}", userId);',
            language="csharp",
        ),
        "js": FixExample(
            before="console.log('api_key', apiKey);",
            after="console.log('api call completed');  // redact secrets",
            language="javascript",
        ),
    },
    "security/world-writable": {
        "py": FixExample(
            before="os.chmod(path, 0o777)",
            after="os.chmod(path, 0o600)  # owner read/write only",
            language="python",
        ),
    },
    "security/vscode-hardcoded-env": {
        "*": FixExample(
            before='// .vscode/launch.json\n"env": { "password": "secret", "api_key": "sk_live_..." }',
            after='// .vscode/launch.json\n"env": { "password": "${env:DB_PASSWORD}" }\n// or use a local untracked .env (gitignored)',
            language="json",
        ),
    },
    "security/http-no-tls": {
        "*": FixExample(
            before='url = "http://api.example.com/data"\nSECURE_SSL_REDIRECT = False',
            after='url = "https://api.example.com/data"\nSECURE_SSL_REDIRECT = True',
            language="text",
        ),
    },
    "security/tls-old": {
        "*": FixExample(
            before="minVersion: 'TLSv1'\nSecurityProtocolType.Tls  // 1.0",
            after="minVersion: 'TLSv1.2'\n// Require TLS 1.2 or 1.3 only",
            language="text",
        ),
    },
    "security/samesite": {
        "*": FixExample(
            before="SameSite=None\nsamesite: 'none'",
            after="SameSite=Lax  # or Strict for session cookies\n# Always pair with Secure flag",
            language="text",
        ),
    },
    "security/csp": {
        "*": FixExample(
            before="Content-Security-Policy: script-src 'unsafe-inline' 'unsafe-eval'",
            after="Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-...'",
            language="text",
        ),
    },
    "error/stack-trace": {
        "py": FixExample(
            before="return jsonify(error=traceback.format_exc()), 500",
            after='logger.exception("request failed")\nreturn jsonify(error="Internal server error"), 500',
            language="python",
        ),
        "cs": FixExample(
            before="return Content(ex.ToString());",
            after='_logger.LogError(ex, "unhandled");\nreturn Problem(detail: "An error occurred.");',
            language="csharp",
        ),
        "js": FixExample(
            before="res.status(500).send(err);",
            after='console.error(err);\nres.status(500).json({ error: "Internal server error" });',
            language="javascript",
        ),
    },
    "auth/weak-password-hash": {
        "py": FixExample(
            before="hashlib.md5(password.encode()).hexdigest()",
            after="bcrypt.hashpw(password.encode(), bcrypt.gensalt())",
            language="python",
        ),
        "*": FixExample(
            before="md5(password) / sha1(password)",
            after="bcrypt / Argon2 / PBKDF2 with salt + work factor",
            language="text",
        ),
    },
    "auth/allow-anonymous": {
        "cs": FixExample(
            before="[AllowAnonymous]\n[HttpGet]\npublic IActionResult Admin() { ... }",
            after="[Authorize(Roles = \"Admin\")]\n[HttpGet]\npublic IActionResult Admin() { ... }",
            language="csharp",
        ),
        "*": FixExample(
            before="permitAll() / AllowAnonymous on sensitive routes",
            after="require authentication + least-privilege roles",
            language="text",
        ),
    },
    "auth/insecure-session": {
        "*": FixExample(
            before="secure=False, httponly=False, samesite=None",
            after="secure=True, httponly=True, samesite='Lax'",
            language="text",
        ),
    },
    "authz/": {
        "cs": FixExample(
            before="[HttpPost]\npublic IActionResult Delete(int id) { ... }",
            after="[Authorize]\n[HttpPost]\npublic IActionResult Delete(int id) { ... }",
            language="csharp",
        ),
        "py": FixExample(
            before="@app.route('/admin')\ndef admin(): ...",
            after='@app.route("/admin")\n@login_required\n@roles_required("admin")\ndef admin(): ...',
            language="python",
        ),
        "*": FixExample(
            before="public endpoint without authorization check",
            after="enforce authn + authz server-side on every sensitive route",
            language="text",
        ),
    },
    "iv-1/": {
        "*": FixExample(
            before="use request input directly in SQL / command / file / redirect",
            after="validate (schema/allow-list) then use safe APIs (parameters, path join sandbox)",
            language="text",
        ),
    },
    "iv-2/": {
        "py": FixExample(
            before="name = request.POST['name']  # no form validation",
            after="form = MyForm(request.POST)\nif form.is_valid():\n    name = form.cleaned_data['name']",
            language="python",
        ),
        "cs": FixExample(
            before="public IActionResult Create([FromBody] UserDto dto) => Ok(dto);",
            after="public IActionResult Create([FromBody] UserDto dto)\n{\n  if (!ModelState.IsValid) return BadRequest(ModelState);\n  ...\n}",
            language="csharp",
        ),
        "js": FixExample(
            before="app.post('/login', (req, res) => { const u = req.body.username; })",
            after="app.post('/login', body('username').trim().isLength({ max: 50 }), (req, res) => {\n  const errors = validationResult(req);\n  ...\n})",
            language="javascript",
        ),
    },
    "iv-7/": {
        "py": FixExample(
            before="f = request.files['upload']\nf.save(f.filename)",
            after="f = request.files['upload']\nif f.mimetype not in ALLOWED and ext not in ALLOWED_EXT:\n    abort(400)\nif f.content_length > MAX_SIZE: abort(400)\nf.save(secure_filename(f.filename))",
            language="python",
        ),
        "cs": FixExample(
            before="public IActionResult Upload(IFormFile file) => Ok();",
            after="public IActionResult Upload(IFormFile file)\n{\n  if (file.Length > MaxBytes) return BadRequest();\n  if (!AllowedTypes.Contains(file.ContentType)) return BadRequest();\n  // store outside web root with generated name\n}",
            language="csharp",
        ),
        "js": FixExample(
            before="multer({ dest: 'uploads/' })",
            after="multer({\n  dest: 'uploads/',\n  limits: { fileSize: 5_000_000 },\n  fileFilter: (req, file, cb) => {\n    if (!ALLOWED.includes(file.mimetype)) return cb(new Error('type'));\n    cb(null, true);\n  },\n})",
            language="javascript",
        ),
    },
    "iv-6/": {
        "*": FixExample(
            before='if blacklist.includes(input): reject',
            after='if not ALLOWLIST_PATTERN.match(input): reject\n# prefer allow-lists over deny-lists',
            language="text",
        ),
    },
    "cloud/s3-public": {
        "*": FixExample(
            before='acl = "public-read"\nblock_public_acls = false',
            after='# private by default\nblock_public_acls   = true\nblock_public_policy = true\n# use signed URLs for temporary access',
            language="hcl",
        ),
    },
    "cloud/open-sg": {
        "*": FixExample(
            before='cidr_blocks = ["0.0.0.0/0"]  # open to world',
            after='cidr_blocks = ["10.0.0.0/8"]  # least-privilege corporate/VPC range\n# open only required ports',
            language="hcl",
        ),
    },
    "cloud/iam-wildcard": {
        "*": FixExample(
            before='"Action": "*", "Resource": "*"',
            after='"Action": ["s3:GetObject"], "Resource": ["arn:aws:s3:::my-bucket/*"]',
            language="json",
        ),
    },
    "iac/secret": {
        "*": FixExample(
            before='password = "tf-secret-value"',
            after='# password from vault / CI secret / SSM — not in .tf source',
            language="hcl",
        ),
    },
    "deps/missing-lockfile": {
        "*": FixExample(
            before="# only package.json / requirements.txt committed",
            after="# also commit:\n# package-lock.json | yarn.lock | poetry.lock | Pipfile.lock | go.sum",
            language="text",
        ),
    },
    "api/no-rate-limit": {
        "js": FixExample(
            before="app.post('/login', handler)",
            after="const rateLimit = require('express-rate-limit');\napp.post('/login', rateLimit({ windowMs: 60_000, max: 20 }), handler)",
            language="javascript",
        ),
        "py": FixExample(
            before='@app.route("/login", methods=["POST"])\ndef login(): ...',
            after='from flask_limiter import Limiter\n@limiter.limit("20/minute")\n@app.route("/login", methods=["POST"])\ndef login(): ...',
            language="python",
        ),
        "cs": FixExample(
            before="[HttpPost] public IActionResult Login() { ... }",
            after='[EnableRateLimiting("auth")]\n[HttpPost] public IActionResult Login() { ... }',
            language="csharp",
        ),
        "*": FixExample(
            before="public API with no throttling",
            after="add rate limiting / WAF / API gateway throttles on public endpoints",
            language="text",
        ),
    },
    "deps/": {
        "cs": FixExample(
            before='<PackageReference Include="Microsoft.Data.OData" Version="5.6.4" />',
            after='<PackageReference Include="Microsoft.Data.OData" Version="5.8.4" />\n// CVE-2018-8269 / CWE-400 — upgrade to 5.8.4+',
            language="csharp",
        ),
        "*": FixExample(
            before="vulnerable PackageReference / npm package version in lockfile or manifest",
            after="upgrade to the fixed version from the CVE advisory; re-run scan and CI SCA",
            language="text",
        ),
    },
    "dos/": {
        "py": FixExample(
            before='pattern = re.compile(request.args["q"])\nzf.extractall("/tmp/out")\ndata = request.get_data()',
            after=(
                "# allow-list patterns only; never compile untrusted regex\n"
                "ALLOWED = re.compile(r\"^[a-z0-9_-]{1,32}$\")\n"
                "if not ALLOWED.fullmatch(request.args.get(\"q\", \"\")):\n"
                "    abort(400)\n"
                "# cap body size and archive expansion\n"
                "app.config[\"MAX_CONTENT_LENGTH\"] = 1_000_000\n"
                "safe_extract(zf, dest, max_total_bytes=10_000_000, max_entries=1000)"
            ),
            language="python",
        ),
        "js": FixExample(
            before="const re = new RegExp(req.query.pattern);\nconst buf = Buffer.alloc(parseInt(req.query.n));",
            after=(
                "// fixed pattern or timeout-capable engine; never new RegExp(userInput)\n"
                "const re = /^[a-z0-9_-]{1,32}$/;\n"
                "const n = Math.min(Number(req.query.n) || 0, 1024);\n"
                "const buf = Buffer.alloc(n);\n"
                "app.use(express.json({ limit: '100kb' }));"
            ),
            language="javascript",
        ),
        "cs": FixExample(
            before='var doc = new XmlDocument();\ndoc.LoadXml(userXml);\nZipFile.ExtractToDirectory(zipPath, dest);',
            after=(
                "var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null };\n"
                "using var reader = XmlReader.Create(stream, settings);\n"
                "// extract zip entries with total size + count caps before writing"
            ),
            language="csharp",
        ),
        "*": FixExample(
            before="unbounded regex / body read / zip extract / user-sized allocation",
            after="timeouts, max body size, max allocation caps, secure XML, bounded archive extraction (CWE-400)",
            language="text",
        ),
    },
    "null/": {
        "java": FixExample(
            before="String name = map.get(key).toString();\nUser u = optional.get();",
            after="Optional.ofNullable(map.get(key)).map(Object::toString).orElse(\"\");\nif (optional.isPresent()) { User u = optional.get(); }",
            language="java",
        ),
        "cs": FixExample(
            before="var email = users.FirstOrDefault().Email;",
            after="var user = users.FirstOrDefault();\nif (user is null) return NotFound();\nvar email = user.Email;",
            language="csharp",
        ),
        "kt": FixExample(
            before="val n = name!!.length",
            after="val n = name?.length ?: 0",
            language="kotlin",
        ),
        "*": FixExample(
            before="obj.member without null check / Optional.get() / FirstOrDefault().X",
            after="null-check, ?., orElse, isPresent, or pattern matching before use (CWE-476)",
            language="text",
        ),
    },
    "secure/deprecated": {
        "*": FixExample(
            before="DES / RC4 / MD5 / BinaryFormatter / pickle.loads",
            after="AES-GCM / SHA-256+ / System.Text.Json / json.loads",
            language="text",
        ),
    },
    "secure/eval-exec": {
        "py": FixExample(
            before="eval(user_code)\nexec(user_code)",
            after="# avoid eval/exec on untrusted input; use safe parsers / sandboxes",
            language="python",
        ),
        "js": FixExample(
            before="eval(userInput)\nnew Function(userInput)()",
            after="// parse structured data with JSON.parse; never eval user input",
            language="javascript",
        ),
    },
}


def _lang_from_path(file_path: str) -> str:
    lower = file_path.lower().replace("\\", "/")
    if lower.endswith((".py", ".pyw", ".pyi")):
        return "py"
    if lower.endswith((".cs", ".cshtml", ".razor")):
        return "cs"
    if lower.endswith((".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx")):
        return "js"
    if lower.endswith((".tf", ".tfvars", ".hcl")):
        return "tf"
    if lower.endswith((".yml", ".yaml")):
        return "yaml"
    if lower.endswith((".json", ".code-workspace")):
        return "json"
    return "*"


def _lookup(rule_id: str, lang: str) -> FixExample | None:
    # Prefer longest matching key (exact or prefix)
    candidates = []
    for key in _EXAMPLES:
        if rule_id == key or rule_id.startswith(key):
            candidates.append(key)
    if not candidates:
        return None
    key = max(candidates, key=len)
    bucket = _EXAMPLES[key]
    if lang in bucket:
        return bucket[lang]
    if lang == "tf" and "tf" not in bucket and "*" in bucket:
        return bucket["*"]
    return bucket.get("*")


def get_fix_example(finding: Finding) -> FixExample | None:
    """Return a before/after fix example for a finding, if available."""
    lang = _lang_from_path(finding.file_path)
    example = _lookup(finding.rule_id, lang)
    if example:
        return example
    # Fall back by policy
    policy_map = {
        "hardcoded_passwords": "policy-1/password-assignment",
        "api_keys": "policy-2/",
        "oauth_secrets": "policy-3/",
        "cloud_access_keys": "policy-4/",
        "certificates_private_keys": "policy-5/",
        "env_var_secrets": "policy-6/",
        "sensitive_config": "policy-7/",
        "vault_management": "policy-8/",
        "sql_injection": "injection/sql",
        "command_injection": "injection/command",
        "nosql_injection": "injection/nosql",
        "xss": "xss/inner-html",
        "path_traversal": "traversal/",
        "csrf": "security/csrf",
        "cryptography": "crypto/weak-hash",
        "transport_security": "security/ssl-verify",
        "debug_mode": "security/debug",
        "sensitive_logs": "security/log-sensitive",
        "error_handling": "error/stack-trace",
        "file_upload_validation": "iv-7/",
        "rate_limiting": "api/no-rate-limit",
        "denial_of_service": "dos/",
        "dependencies": "deps/",
        "null_pointer": "null/",
        "dependencies": "deps/missing-lockfile",
        "cloud_infra": "cloud/s3-public",
        "authentication": "auth/allow-anonymous",
        "authorization": "authz/",
    }
    if finding.policy and finding.policy in policy_map:
        return _lookup(policy_map[finding.policy], lang)
    return None


def format_before_after(
    finding: Finding,
    *,
    prefer_snippet_as_before: bool = True,
) -> tuple[str | None, str | None, str]:
    """
    Return (before, after, note) for display.
    Uses the real code snippet as "before" when available.
    """
    example = get_fix_example(finding)
    if not example:
        if finding.snippet and finding.remediation:
            return finding.snippet, f"# Fix: {finding.remediation}", ""
        return finding.snippet, None, finding.remediation or ""

    before = finding.snippet if (prefer_snippet_as_before and finding.snippet) else example.before
    return before, example.after, example.note or (finding.remediation or "")
