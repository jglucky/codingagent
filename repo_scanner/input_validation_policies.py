"""Input validation policy definitions and detection rules."""

from __future__ import annotations

import re
from dataclasses import dataclass

from .rules import ALL_CODE_EXTENSIONS, SecurityRule


@dataclass(frozen=True)
class InputValidationPolicy:
    id: str
    number: int
    title: str
    description: str


INPUT_VALIDATION_POLICIES: list[InputValidationPolicy] = [
    InputValidationPolicy(
        id="user_input_validated",
        number=1,
        title="All User Input Is Validated",
        description="User-supplied data must be validated before use in application logic.",
    ),
    InputValidationPolicy(
        id="server_side_validation",
        number=2,
        title="Server-Side Validation for External Data",
        description="All externally supplied data must be validated on the server, not only on the client.",
    ),
    InputValidationPolicy(
        id="input_length_restrictions",
        number=3,
        title="Input Length Restrictions",
        description="Input fields and API parameters must enforce maximum length limits.",
    ),
    InputValidationPolicy(
        id="input_type_validation",
        number=4,
        title="Input Type Validation",
        description="Inputs must be validated for expected data types before processing.",
    ),
    InputValidationPolicy(
        id="special_char_sanitization",
        number=5,
        title="Special Character Sanitization",
        description="User input must be sanitized or escaped where special characters pose a risk.",
    ),
    InputValidationPolicy(
        id="allowlist_validation",
        number=6,
        title="Allow-List Validation Preferred",
        description="Validation must use allow-lists; deny-list/blocklist approaches are discouraged.",
    ),
    InputValidationPolicy(
        id="file_upload_validation",
        number=7,
        title="File Upload Validation",
        description="File uploads must validate type, size, extension, and MIME type on the server.",
    ),
]

IV_POLICY_BY_ID = {policy.id: policy for policy in INPUT_VALIDATION_POLICIES}

WEB_EXTENSIONS = frozenset({
    ".py", ".pyw", ".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".rb", ".php",
    ".cs", ".cshtml", ".razor",
    ".vue", ".svelte", ".html", ".htm", ".jsp", ".erb",
})

CSHARP_EXTENSIONS = frozenset({".cs", ".cshtml", ".razor"})
PYTHON_EXTENSIONS = frozenset({".py", ".pyw"})
HTML_EXTENSIONS = frozenset({".html", ".htm", ".vue", ".jsx", ".tsx", ".jsp", ".erb", ".cshtml", ".razor"})


def _iv_rule(
    rule_id: str,
    policy_id: str,
    title: str,
    severity: str,
    pattern: str,
    message: str,
    remediation: str,
    *,
    extensions: frozenset[str] | None = None,
    flags: int = re.IGNORECASE,
) -> SecurityRule:
    return SecurityRule(
        id=rule_id,
        title=title,
        category="input_validation",
        policy=policy_id,
        severity=severity,
        pattern=re.compile(pattern, flags),
        message=message,
        remediation=remediation,
        extensions=extensions,
    )


INPUT_VALIDATION_RULES: list[SecurityRule] = [
    # Policy 1: All user input validated
    _iv_rule(
        "iv-1/input-in-sql",
        "user_input_validated",
        "Unvalidated Input in SQL",
        "high",
        r"(?i)(?:execute|query|rawQuery|raw|SqlCommand|ExecuteReader|ExecuteNonQuery|FromSqlRaw|FromSqlInterpolated)\s*\([^)]*"
        r"(?:req\.(?:body|query|params)|request\.(?:args|form|GET|POST)|"
        r"\$_GET|\$_POST|ctx\.request|Request\.(?:Query|Form|Params)|HttpContext\.Request|\[From)",
        "Externally supplied data used in a database query without visible validation.",
        "Validate and parameterize all user input before constructing SQL statements.",
        extensions=WEB_EXTENSIONS,
    ),
    _iv_rule(
        "iv-1/input-in-command",
        "user_input_validated",
        "Unvalidated Input in Command Execution",
        "high",
        r"(?i)(?:exec|system|popen|spawn|subprocess\.(?:call|run)|Process\.Start)\s*\([^)]*"
        r"(?:req\.|request\.|\$_GET|\$_POST|params\.|args\.|Request\.|HttpContext\.|\[From)",
        "Externally supplied data passed to a command execution function without validation.",
        "Validate input against a strict allow-list before any shell or process invocation.",
        extensions=WEB_EXTENSIONS,
    ),
    _iv_rule(
        "iv-1/input-in-file-op",
        "user_input_validated",
        "Unvalidated Input in File Operation",
        "high",
        r"(?i)(?:open|readFile|readFileSync|sendFile|createReadStream|FileInputStream|"
        r"File\.(?:Open|ReadAllText|ReadAllBytes|WriteAllText))\s*\([^)]*"
        r"(?:req\.|request\.|\$_GET|\$_POST|params\.|query\.|Request\.|HttpContext\.|\[From)",
        "Externally supplied data used in a file operation without visible validation.",
        "Validate and canonicalize file paths; restrict to an allowed directory.",
        extensions=WEB_EXTENSIONS,
    ),
    _iv_rule(
        "iv-1/input-in-redirect",
        "user_input_validated",
        "Unvalidated Input in Redirect",
        "medium",
        r"(?i)(?:redirect|res\.redirect|HttpResponseRedirect|window\.location|Redirect|LocalRedirect|RedirectToAction)\s*[=(]\s*[^)]*"
        r"(?:req\.|request\.|params\.|query\.|\$_GET|Request\.|HttpContext\.|\[From)",
        "Externally supplied data used in a redirect without visible validation.",
        "Validate redirect targets against an allow-list of permitted URLs.",
        extensions=WEB_EXTENSIONS,
    ),
    _iv_rule(
        "iv-1/direct-body-assignment",
        "user_input_validated",
        "Direct User Input Assignment",
        "medium",
        r"(?i)(?:const|let|var)\s+\w+\s*=\s*req\.(?:body|query|params)(?:\.\w+|\[)",
        "Request data assigned directly without visible inline validation.",
        "Validate input with a schema library (Joi, Zod, Pydantic) immediately after extraction.",
        extensions=frozenset({".js", ".jsx", ".ts", ".tsx"}),
    ),

    # Policy 2: Server-side validation
    _iv_rule(
        "iv-2/spring-no-valid",
        "server_side_validation",
        "Missing @Valid on Request Body",
        "high",
        r"@RequestBody(?!\s*\([^)]*@Valid)[^;{]*(?:public|private|protected)",
        "Spring controller accepts a request body without @Valid annotation.",
        "Add @Valid to enforce server-side bean validation on all request bodies.",
        extensions=frozenset({".java"}),
    ),

    _iv_rule(
        "iv-2/client-only-html5",
        "server_side_validation",
        "Client-Only HTML5 Validation",
        "medium",
        r"<input[^>]+required[^>]*>",
        "HTML form uses client-side required attribute; server-side validation must also exist.",
        "Mirror all client-side constraints with server-side validation logic.",
        extensions=HTML_EXTENSIONS,
    ),
    _iv_rule(
        "iv-2/client-only-pattern",
        "server_side_validation",
        "Client-Only Pattern Validation",
        "medium",
        r"<input[^>]+pattern\s*=[^>]*>",
        "HTML pattern attribute provides client-only validation.",
        "Enforce the same pattern rules on the server using a validation library.",
        extensions=HTML_EXTENSIONS,
    ),
    _iv_rule(
        "iv-2/php-superglobal-direct",
        "server_side_validation",
        "Direct PHP Superglobal Access",
        "medium",
        r"\$_(?:GET|POST|REQUEST|COOKIE)\s*\[[^\]]+\]",
        "PHP superglobal accessed directly; use filter_input() with validation filters.",
        "Validate all superglobal input server-side with filter_input() or a validation framework.",
        extensions=frozenset({".php"}),
    ),

    # Policy 3: Input length restrictions
    _iv_rule(
        "iv-3/html-input-no-maxlength",
        "input_length_restrictions",
        "Missing maxlength on Input",
        "medium",
        r"<input(?![^>]*maxlength)[^>]+type\s*=\s*['\"]?(?:text|email|password|search|url|tel)['\"]?[^>]*>",
        "HTML text input lacks a maxlength attribute.",
        "Set maxlength on inputs and enforce the same limit server-side.",
        extensions=HTML_EXTENSIONS,
    ),
    _iv_rule(
        "iv-3/textarea-no-maxlength",
        "input_length_restrictions",
        "Missing maxlength on Textarea",
        "medium",
        r"<textarea(?![^>]*maxlength)[^>]*>",
        "Textarea element lacks a maxlength attribute.",
        "Add maxlength and enforce length limits in server-side validation.",
        extensions=HTML_EXTENSIONS,
    ),
    _iv_rule(
        "iv-3/react-input-no-maxlength",
        "input_length_restrictions",
        "Missing maxLength on React Input",
        "medium",
        r"<input(?![^>]*maxLength)[^>]+type\s*=\s*['\"]?(?:text|email|password)['\"]?",
        "React input component lacks maxLength prop.",
        "Add maxLength and validate length server-side with .isLength() or equivalent.",
        extensions=frozenset({".jsx", ".tsx", ".js", ".ts"}),
    ),
    _iv_rule(
        "iv-3/validator-no-length",
        "input_length_restrictions",
        "Validator Without Length Check",
        "medium",
        r"(?i)(?:body|check|param|query)\s*\(\s*['\"][^'\"]+['\"]\s*\)(?![^;]*\.isLength|[^;]*\.max\(|[^;]*Length\()",
        "Validation chain defined without a visible length constraint.",
        "Add .isLength({ max: N }) or equivalent length validation to all string fields.",
        extensions=frozenset({".js", ".ts", ".jsx", ".tsx"}),
    ),
    _iv_rule(
        "iv-3/flask-stringfield-no-length",
        "input_length_restrictions",
        "Form Field Without Length Validator",
        "medium",
        r"(?i)StringField\s*\([^)]*\)(?!.*validators\s*=\s*\[[^\]]*Length)",
        "WTForms StringField defined without a Length validator.",
        "Add validators=[Length(max=N)] to all string form fields.",
        extensions=PYTHON_EXTENSIONS,
    ),
    # Policy 4: Input type validation
    _iv_rule(
        "iv-4/parseint-no-check",
        "input_type_validation",
        "Unchecked parseInt on Input",
        "medium",
        r"parseInt\s*\(\s*(?:req\.|request\.|params\.|query\.|body\.|\$_)",
        "parseInt called on user input without visible type validation.",
        "Validate input is numeric with .isInt() or Number.isInteger() before parsing.",
        extensions=frozenset({".js", ".jsx", ".ts", ".tsx"}),
    ),
    _iv_rule(
        "iv-4/number-conversion-no-check",
        "input_type_validation",
        "Unchecked Number Conversion",
        "medium",
        r"Number\s*\(\s*(?:req\.|request\.|params\.|query\.|\$_)",
        "Number() called on user input without visible validation.",
        "Validate type and range before converting user input to a number.",
        extensions=frozenset({".js", ".jsx", ".ts", ".tsx"}),
    ),
    _iv_rule(
        "iv-4/python-int-cast",
        "input_type_validation",
        "Unchecked int() Cast on Input",
        "medium",
        r"int\s*\(\s*request\.(?:GET|POST|args|form)",
        "int() cast applied to Django/Flask request data without visible validation.",
        "Use type-safe parsing with try/except and range checks, or Pydantic/Marshmallow schemas.",
        extensions=PYTHON_EXTENSIONS,
    ),
    _iv_rule(
        "iv-4/csharp-parse-no-check",
        "input_type_validation",
        "Unchecked Parse of Request Input (C#)",
        "medium",
        r"(?i)(?:int|long|decimal|double|float|Guid|DateTime)\.Parse\s*\(\s*(?:Request\.|HttpContext\.Request|\[From)",
        "Parse() called on request data without TryParse or prior type validation.",
        "Use TryParse with range checks, model binding with typed parameters, or FluentValidation.",
        extensions=CSHARP_EXTENSIONS,
    ),
    _iv_rule(
        "iv-4/validator-no-type",
        "input_type_validation",
        "Validator Without Type Check",
        "medium",
        r"(?i)(?:body|check|param|query)\s*\(\s*['\"][^'\"]+['\"]\s*\)\s*\.trim\(\)",
        "Validation chain trims input but does not enforce a specific data type.",
        "Add .isEmail(), .isInt(), .isUUID(), or equivalent type validation.",
        extensions=frozenset({".js", ".ts", ".jsx", ".tsx"}),
    ),
    _iv_rule(
        "iv-4/spring-no-type-annotation",
        "input_type_validation",
        "Request Parameter Without Type Constraint",
        "low",
        r"@RequestParam\s*\(\s*['\"][^'\"]+['\"]\s*\)\s+String\s+\w+",
        "Spring request parameter accepted as String without type or format validation.",
        "Use typed parameters with @Min/@Max/@Email or a custom validator.",
        extensions=frozenset({".java"}),
    ),

    # Policy 5: Special character sanitization
    _iv_rule(
        "iv-5/innerhtml-user-input",
        "special_char_sanitization",
        "Unsanitized Input in innerHTML",
        "high",
        r"(?i)(?:innerHTML|outerHTML)\s*=\s*[^;]*(?:req\.|request\.|params\.|query\.|body\.|\$_|user)",
        "User input assigned to innerHTML without visible sanitization.",
        "Sanitize with DOMPurify or escape HTML entities before rendering.",
        extensions=frozenset({".js", ".jsx", ".ts", ".tsx", ".html"}),
    ),
    _iv_rule(
        "iv-5/react-dangerous-html",
        "special_char_sanitization",
        "Unsanitized dangerouslySetInnerHTML",
        "high",
        r"dangerouslySetInnerHTML\s*=\s*\{\s*(?!\s*\{[^}]*sanitize|DOMPurify)[^}]*(?:props\.|state\.|req\.|user|input)",
        "dangerouslySetInnerHTML used with user-controlled content without sanitization.",
        "Pass content through DOMPurify.sanitize() before rendering.",
        extensions=frozenset({".jsx", ".tsx", ".js", ".ts"}),
    ),
    _iv_rule(
        "iv-5/vue-v-html",
        "special_char_sanitization",
        "Unsanitized v-html Directive",
        "high",
        r'v-html\s*=\s*["\'][^"\']*(?:user|input|request|params|query)',
        "Vue v-html directive used with user-controlled data without sanitization.",
        "Sanitize HTML content or use text interpolation instead of v-html.",
        extensions=frozenset({".vue", ".js", ".ts"}),
    ),
    _iv_rule(
        "iv-5/django-safe-filter",
        "special_char_sanitization",
        "Django |safe Filter on User Data",
        "high",
        r"\{\{\s*\w+\s*\|\s*safe\s*\}\}",
        "Django template marks variable as safe; ensure content is sanitized server-side.",
        "Only apply |safe to content that has been sanitized with bleach or equivalent.",
        extensions=frozenset({".html", ".htm", ".django"}),
    ),
    _iv_rule(
        "iv-5/razor-html-raw",
        "special_char_sanitization",
        "Unsanitized Html.Raw in Razor",
        "high",
        r"(?i)Html\.Raw\s*\(",
        "Razor Html.Raw bypasses encoding; user-controlled content can enable XSS.",
        "Sanitize untrusted HTML or rely on default Razor encoding.",
        extensions=frozenset({".cshtml", ".razor", ".cs"}),
    ),
    _iv_rule(
        "iv-5/template-no-escape",
        "special_char_sanitization",
        "Template Renders Raw User Input",
        "medium",
        r"(?i)(?:render|render_template|res\.render)\([^)]*(?:req\.|request\.|\$_)(?!.*escape|sanitize)",
        "Template rendered with request data; ensure output is escaped.",
        "Enable auto-escaping in templates and sanitize user-supplied HTML content.",
        extensions=WEB_EXTENSIONS,
    ),

    # Policy 6: Allow-list over deny-list
    _iv_rule(
        "iv-6/blacklist-validation",
        "allowlist_validation",
        "Deny-List Validation Used",
        "medium",
        r"(?i)(?:blacklist|blocklist|denylist|deny[_-]?list|banned[_-]?(?:chars|words|list))\s*[=:]",
        "Deny-list (blacklist) validation pattern detected.",
        "Replace deny-list checks with allow-list validation that permits only known-good values.",
        extensions=ALL_CODE_EXTENSIONS,
    ),
    _iv_rule(
        "iv-6/blocklist-check",
        "allowlist_validation",
        "Blocklist Check for Input",
        "medium",
        r"(?i)(?:if|when)\s*\([^)]*(?:blacklist|blocklist|denylist|banned|forbidden|illegal)[^)]*(?:includes|contains|match|indexOf)",
        "Input validated by checking against a blocklist.",
        "Define an allow-list of permitted values and reject anything not in the list.",
        extensions=ALL_CODE_EXTENSIONS,
    ),
    _iv_rule(
        "iv-6/strip-bad-chars",
        "allowlist_validation",
        "Character Stripping Instead of Allow-List",
        "low",
        r"(?i)(?:replace|strip|remove)\s*\([^)]*(?:bad|illegal|invalid|forbidden)[^)]*char",
        "Input sanitized by removing bad characters (deny-list approach).",
        "Validate against an allow-list regex or enumerated set of permitted characters.",
        extensions=ALL_CODE_EXTENSIONS,
    ),

    # Policy 7: File upload validation
    _iv_rule(
        "iv-7/multer-no-filter",
        "file_upload_validation",
        "Multer Upload Without fileFilter",
        "high",
        r"multer\s*\(\s*\{(?![^}]*fileFilter)",
        "Multer configured without a fileFilter to validate file types.",
        "Add fileFilter to check MIME type and extension against an allow-list.",
        extensions=frozenset({".js", ".ts", ".jsx", ".tsx"}),
    ),
    _iv_rule(
        "iv-7/multer-no-limits",
        "file_upload_validation",
        "Multer Upload Without Size Limits",
        "medium",
        r"multer\s*\(\s*\{(?![^}]*limits)",
        "Multer configured without file size limits.",
        "Set limits.fileSize to enforce maximum upload size on the server.",
        extensions=frozenset({".js", ".ts", ".jsx", ".tsx"}),
    ),
    _iv_rule(
        "iv-7/upload-no-mimetype",
        "file_upload_validation",
        "Upload Handler Without MIME Check",
        "high",
        r"(?i)(?:upload\.(?:single|array|fields)|busboy|formidable)\s*\([^)]*\)(?!.*mimetype|mime|contentType|fileFilter)",
        "File upload handler lacks visible MIME type validation.",
        "Verify Content-Type/MIME type server-side against an allow-list, not just extension.",
        extensions=frozenset({".js", ".ts", ".jsx", ".tsx", ".py"}),
    ),
    _iv_rule(
        "iv-7/form-accept-only",
        "file_upload_validation",
        "Client-Only accept Attribute on File Input",
        "medium",
        r"<input[^>]+type\s*=\s*['\"]file['\"][^>]+accept\s*=[^>]*>",
        "File input uses accept attribute which is client-side only.",
        "Validate file extension, MIME type, and size on the server after upload.",
        extensions=HTML_EXTENSIONS,
    ),
    _iv_rule(
        "iv-7/flask-upload-no-check",
        "file_upload_validation",
        "Flask File Upload Without Validation",
        "high",
        r"request\.files\[[^\]]+\](?!.*content_type|mimetype|allowed|extension)",
        "Flask file upload accessed without visible type or size validation.",
        "Validate filename extension, MIME type, and file size before processing uploads.",
        extensions=PYTHON_EXTENSIONS,
    ),
    _iv_rule(
        "iv-7/spring-multipart-no-check",
        "file_upload_validation",
        "Spring Multipart Upload Without Validation",
        "high",
        r"@RequestParam\s*\([^)]*MultipartFile[^)]*\)",
        "Spring multipart file accepted without visible validation annotations.",
        "Validate file size, content type, and extension before storing uploaded files.",
        extensions=frozenset({".java"}),
    ),
]