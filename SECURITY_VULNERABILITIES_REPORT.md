# Security Vulnerabilities Report

This report documents potential security vulnerabilities identified in the Stytch Python SDK repository.

---

## High Severity

### 1. Unvalidated `environment` Parameter Allows SSRF and Credential Leakage

**Location:** `stytch/core/client_base.py` (lines 70-79)

**Description:** When the `environment` parameter is set to a value other than `"test"` or `"live"`, it is returned directly as the API base URL without any validation. Unlike `custom_base_url`, there is no HTTPS scheme validation.

**Vulnerable Code:**
```python
if env == "test":
    return "https://test.stytch.com/"
elif env == "live":
    return "https://api.stytch.com/"

return env  # ← No validation! Arbitrary URL accepted
```

**Impact:**
- **SSRF:** An attacker who can influence the `environment` value (e.g., via config file, environment variable, or dependency injection) could redirect all API requests to a malicious server
- **Credential Leakage:** All requests include HTTP Basic Auth with `project_id` and `secret` - these would be sent to the attacker's server
- **JWKS Poisoning:** The `PyJWKClient` fetches signing keys from the base URL - a malicious server could return attacker-controlled keys for JWT verification

**Recommendation:** Validate that custom environment URLs use HTTPS, similar to `custom_base_url`:
```python
elif env == "live":
    return "https://api.stytch.com/"

# Custom environment - must use HTTPS
if not env.startswith("https://"):
    raise ValueError("custom environment URL must use HTTPS scheme")
if not env.endswith("/"):
    env = env + "/"
return env
```

---

### 2. Unvalidated `fraud_environment` Parameter

**Location:** `stytch/core/client_base.py` (lines 27-30)

**Description:** The `fraud_environment` parameter is used directly as `fraud_base_url` with no validation. All fraud/telemetry requests would be sent to an arbitrary URL.

**Vulnerable Code:**
```python
fraud_base_url = "https://telemetry.stytch.com"
if fraud_environment is not None:
    fraud_base_url = fraud_environment  # No validation
```

**Impact:** Same as above - SSRF and potential data exfiltration if the parameter can be influenced.

**Recommendation:** Add HTTPS validation for `fraud_environment` when provided.

---

## Medium Severity

### 3. Hardcoded Credentials in README Documentation

**Location:** `README.md` (lines 57, 79, 99, 115)

**Description:** The README contains what appear to be real API credentials in example code:
- `secret="secret-live-80JASucyk7z_G8Z-7dVwZVGXL5NT_qGAQ2I="`
- `project_id="project-live-c60c0abe-c25a-4472-a9ed-320c6667d317"`

**Impact:** If these are production credentials that were committed:
- They may have been exposed in git history
- They could be used to access the Stytch project
- They should be considered compromised and rotated immediately

**Recommendation:** Replace with placeholder values like `"your-project-id"` and `"your-secret"` in documentation examples.

---

### 4. Test Credentials in Version Control

**Location:** `test/constants.py`

**Description:** Test tokens and credentials are stored in the repository:
- `TEST_MAGIC_TOKEN`, `TEST_OAUTH_TOKEN`, `TEST_SESSION_TOKEN`
- `TEST_CRYPTO_SIGNATURE`, `TEST_PW_HASH`

**Impact:** If these are valid sandbox credentials, they could be abused. Test credentials should ideally be loaded from environment variables rather than committed.

**Recommendation:** Use environment variables for integration test credentials; add `test/constants.py` to `.gitignore` if it contains secrets, or use placeholder values with real creds loaded at runtime.

---

## Low Severity / Informational

### 5. Deprecated `asyncio.get_event_loop()` in AsyncClient

**Location:** `stytch/core/http/client.py` (line 141)

**Description:** `asyncio.get_event_loop()` is deprecated in Python 3.10+ and may be removed in future versions. In Python 3.10+, `asyncio.get_event_loop()` raises a DeprecationWarning when called from an async context.

**Recommendation:** Use `asyncio.get_running_loop()` when in an async context, or handle the destructor more carefully for async cleanup.

---

### 6. Dependency Audit

**Description:** Run `pip-audit` in your deployment environment to check for known vulnerabilities in dependencies. The project's direct dependencies (aiohttp, requests, pydantic, pyjwt) should be kept up to date.

**Recommendation:** Add `pip-audit` to CI/CD pipeline and address any reported vulnerabilities.

---

## Positive Security Findings

The following security measures are properly implemented:

- **JWT Verification:** `stytch/shared/jwt_helpers.py` correctly restricts algorithms to `RS256` only (prevents algorithm confusion attacks), verifies signature, audience, issuer, expiration, and other claims
- **custom_base_url Validation:** HTTPS scheme is enforced for `custom_base_url` in both main client and SamlShield client
- **No SSL Verification Disabled:** No instances of `verify=False` or similar that would disable certificate validation
- **No Dangerous Deserialization:** No use of `pickle`, `yaml.load`, or `marshal.loads` with untrusted input
- **No Command/Code Injection:** No use of `eval`, `exec`, `os.system`, or `subprocess` with user input
- **URL Encoding:** Path parameters in `ApiBase.url_for` are properly URL-encoded with `urllib.parse.quote`

---

## Summary

| Severity | Count | Priority Actions |
|----------|-------|------------------|
| High | 2 | Fix environment and fraud_environment validation |
| Medium | 2 | Rotate/remove hardcoded credentials |
| Low | 2 | Update deprecated APIs, add dependency auditing |
