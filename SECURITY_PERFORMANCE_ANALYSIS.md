# AuthThingie2 Comprehensive Security & Performance Analysis

**Analysis Date:** 2026-01-04
**Branch:** claude/analyze-security-performance-3cy4j
**Project:** AuthThingie2 - Go Authentication Service

---

## Executive Summary

This comprehensive analysis examined AuthThingie2 across five critical dimensions: security, concurrency, data access, code quality, and performance. The analysis identified **4 CRITICAL**, **12 HIGH**, **23 MEDIUM**, and **18 LOW** severity issues.

### Issue Distribution

| Severity | Security | Concurrency | Data Access | Code Quality | Performance | Total |
|----------|----------|-------------|-------------|--------------|-------------|-------|
| CRITICAL | 1 | 3 | 0 | 0 | 0 | **4** |
| HIGH | 4 | 2 | 1 | 0 | 5 | **12** |
| MEDIUM | 7 | 5 | 4 | 3 | 4 | **23** |
| LOW | 5 | 3 | 7 | 8 | 3 | **18** |

### Key Concerns
1. **Open Redirect Vulnerability** - Critical security flaw enabling phishing attacks
2. **Race Conditions** - Multiple data races in concurrent code paths
3. **Deadlock Potential** - Lock ordering violations in login limiter
4. **Resource Leaks** - HTTP response bodies not closed, unbounded caches

---

## CRITICAL SEVERITY ISSUES (4)

### C1. Open Redirect Vulnerability
**Category:** Security
**Files:**
- `internal/handlers/login.go:216-226`
- `internal/handlers/totp.go:165-175`
- `internal/handlers/notices.go:20-36`

**Description:** The `redirect_uri` parameter is not validated before being used in HTTP redirects. An attacker can craft a malicious login URL that redirects users to an external phishing site after authentication.

**Attack Scenario:**
1. Attacker crafts: `https://auth.example.com/login?redirect_uri=https://evil.com/phishing`
2. User successfully authenticates
3. User is redirected to attacker-controlled site

**Evidence:**
```go
// login.go:216-226
if redirectURL == "" {
    redirectURL = "/"
}
// NO VALIDATION - redirectURL directly from user input
http.Redirect(w, r, redirectURL, http.StatusFound)
```

**Recommended Fix:**
```go
func validateRedirectURI(uri string) bool {
    if uri == "" || uri == "/" {
        return true
    }
    parsed, err := url.Parse(uri)
    if err != nil {
        return false
    }
    // Only allow relative URLs
    if parsed.Scheme != "" || parsed.Host != "" {
        return false
    }
    if !strings.HasPrefix(uri, "/") || strings.HasPrefix(uri, "//") {
        return false
    }
    return true
}
```

---

### C2. Potential Deadlock in Login Limiter
**Category:** Concurrency
**File:** `internal/loginlimit/login_limit.go:156-179`

**Description:** Lock ordering violation between `lockLock` and `failureLock` can cause deadlock.

**Deadlock Scenario:**
- Thread A: `MarkFailedAttempt` → acquires `failureLock` → calls `lockAccount` → waits for `lockLock`
- Thread B: `IsAccountLocked` → acquires `lockLock` → (potential concurrent modification)

**Evidence:**
```go
func (iml *InMemoryLoginLimiter) MarkFailedAttempt(key string) (int, error) {
    if iml.IsAccountLocked(key) {  // Acquires lockLock
        return 0, ErrAccountLocked
    }
    iml.failureLock.Lock()  // Acquires failureLock
    defer iml.failureLock.Unlock()
    // ...
    if len(cleanedAccountFailures) >= iml.maxFailures {
        iml.lockAccount(key)  // Acquires lockLock while failureLock held!
    }
}
```

**Recommended Fix:**
1. Defer `lockAccount` call until after releasing `failureLock`
2. Or use a single mutex for both maps
3. Document and enforce consistent lock ordering

---

### C3. Race Condition on eventStreamInitialized
**Category:** Concurrency
**File:** `internal/trueip/docker_provider.go:52, 143, 149`

**Description:** The `eventStreamInitialized` boolean is read/written without synchronization.

**Evidence:**
```go
type dockerProvider struct {
    eventStreamInitialized bool  // No mutex protection
    updateLock             sync.RWMutex  // Only protects activeIPs
}

func (dp *dockerProvider) eventListener(ctx context.Context) {
    dp.eventStreamInitialized = true   // WRITE without lock
    dp.eventStreamInitialized = false  // WRITE without lock
}

func (dp *dockerProvider) Active() bool {
    return dp.eventStreamInitialized  // READ without lock
}
```

**Recommended Fix:**
```go
type dockerProvider struct {
    eventStreamInitialized atomic.Bool
}
```

---

### C4. Non-Thread-Safe AddRule Method
**Category:** Concurrency
**File:** `internal/rules/analyzer.go:179-181`

**Description:** `AddRule` modifies the `rules` slice without acquiring the lock, while `Rules()` reads it with a read lock.

**Evidence:**
```go
func (a *ViperConfigAnalyzer) AddRule(r Rule) {
    a.rules = append(a.rules, r)  // NO LOCK - Race condition!
}

func (a *ViperConfigAnalyzer) Rules() []Rule {
    a.lock.RLock()  // Properly locked
    defer a.lock.RUnlock()
    // ...
}
```

**Recommended Fix:**
```go
func (a *ViperConfigAnalyzer) AddRule(r Rule) {
    a.lock.Lock()
    defer a.lock.Unlock()
    a.rules = append(a.rules, r)
}
```

---

## HIGH SEVERITY ISSUES (12)

### H1. Missing CSRF Protection
**Category:** Security
**Files:** `internal/handlers/login.go`, `internal/handlers/totp.go`, `internal/handlers/admin.go`

**Description:** No CSRF tokens on state-changing operations. Cross-Origin Protection has bypasses for `/forward` and `/auth`.

**Vulnerable Operations:**
- Password changes (`/edit_self/password`)
- User creation/deletion (`/admin/users/*`)
- TOTP enrollment/disable
- WebAuthn key management

**Recommended Fix:** Implement CSRF token generation and validation with `SameSite=Strict` cookies.

---

### H2. Session Fixation Vulnerability
**Category:** Security
**Files:** `internal/middlewares/session/session.go:204-206`, `internal/handlers/login.go:204-212`

**Description:** Session ID is not regenerated after successful authentication.

**Attack Scenario:**
1. Attacker obtains/sets victim's session cookie
2. Victim logs in with that session
3. Attacker now has authenticated session

**Recommended Fix:**
```go
func (s *Session) RegenerateID() error {
    newID, err := generateSessionID()
    if err != nil {
        return err
    }
    s.SessionID = newID
    return nil
}
// Call before PlaceUserInSession
```

---

### H3. Basic Auth MFA Bypass
**Category:** Security
**Files:** `internal/middlewares/session/user.go:96-134`, `internal/handlers/forward.go:134-144`

**Description:** MFA enforcement for Basic Auth only checked in forward handler, not globally.

**Recommended Fix:** Move MFA enforcement into `GetUserFromRequestAllowFallback`.

---

### H4. TOTP Encryption Key Derivation Weakness
**Category:** Security
**Files:** `internal/salt/salt.go:75-82`, `internal/totp/cipher.go:14-34`

**Issues:**
- No validation of `server.secret_key` entropy
- Salt stored at predictable location
- PBKDF2 iteration count (600k) below OWASP recommendation (1M+)

---

### H5. Unbuffered Channel Blocking Risk
**Category:** Concurrency
**File:** `internal/trueip/docker_provider.go:93, 246`

**Description:** The `cleanup` channel is unbuffered and could block indefinitely.

**Recommended Fix:**
```go
cleanup: make(chan struct{}, 1)  // Buffered
```

---

### H6. Concurrent Config Listener Writes
**Category:** Concurrency
**File:** `internal/config/config.go:100-107`

**Description:** Multiple config listeners spawn as goroutines, potentially causing concurrent writes.

---

### H7. No Transaction Support for Multi-Step Operations
**Category:** Data Access
**File:** `internal/db/sqlite/sqlite.go`

**Description:** No transaction support for operations like `DeleteUser` which modifies multiple resources.

---

### H8. HTTP Response Body Not Closed
**Category:** Performance
**File:** `internal/healthcheck/healthcheck.go:33-41`

**Description:** Response body never closed, causing connection leaks.

**Recommended Fix:**
```go
res, err := client.Do(req)
if err != nil {
    return err
}
defer res.Body.Close()
io.Copy(io.Discard, res.Body)
```

---

### H9. Unbounded TTL Cache Growth
**Category:** Performance
**Files:** `internal/handlers/authn.go:30`, `internal/pwmigrate/userlocker.go:17`, `internal/ftue/handlers.go:26`

**Description:** TTL caches have no capacity limits; under attack can exhaust memory.

**Recommended Fix:**
```go
ttlcache.WithCapacity[string, *webauthn.SessionData](1000)
```

---

### H10. Unbounded Goroutine Spawning for Password Migration
**Category:** Performance
**Files:** `internal/handlers/login.go:179-183`, `internal/middlewares/session/user.go:127-131`

**Description:** Password migrations spawn goroutines without limits.

**Recommended Fix:** Use worker pool with bounded concurrency.

---

### H11. No Database Connection Pool Configuration
**Category:** Performance
**File:** `internal/db/sqlite/sqlite.go:58-72`

**Description:** No `SetMaxOpenConns`, `SetMaxIdleConns`, or connection lifetime settings.

**Recommended Fix:**
```go
database.SetMaxOpenConns(25)
database.SetMaxIdleConns(5)
database.SetConnMaxLifetime(5 * time.Minute)
```

---

### H12. In-Memory Login Limiter State Growth
**Category:** Performance
**File:** `internal/loginlimit/login_limit.go:32-42`

**Description:** Maps grow indefinitely under distributed brute force attacks.

---

## MEDIUM SEVERITY ISSUES (23)

### Security (7)
| ID | Issue | File | Line |
|----|-------|------|------|
| M1 | Weak CSP with `unsafe-eval` | `internal/middlewares/securityheaders/security_headers.go` | 20 |
| M2 | SameSite=Lax instead of Strict | `internal/middlewares/session/user.go` | 144 |
| M3 | Password migration no error handling | `internal/handlers/login.go` | 179-183 |
| M4 | No rate limiting on password changes | `internal/handlers/self_config.go` | 42-95 |
| M5 | Argon2 parameters could be stronger | `internal/argon/argon2.go` | 23-27 |
| M6 | WebAuthn session cache unbounded | `internal/handlers/authn.go` | 30 |
| M7 | Missing nonce validation in TOTP cipher | `internal/totp/cipher.go` | 36-61 |

### Concurrency (5)
| ID | Issue | File | Line |
|----|-------|------|------|
| M8 | Goroutine leak in login limiter | `internal/loginlimit/login_limit.go` | 71-79 |
| M9 | TTL cache cleanup goroutines no shutdown | `internal/handlers/authn.go` | 34 |
| M10 | setupNeeded cache not thread-safe | `internal/db/sqlite/sqlite.go` | 452-531 |
| M11 | Password migration goroutines untracked | `internal/handlers/login.go` | 179-183 |
| M12 | Config write race condition | `internal/config/config.go` | 184-218 |

### Data Access (4)
| ID | Issue | File | Line |
|----|-------|------|------|
| M13 | No connection pool configuration | `internal/db/sqlite/sqlite.go` | 58-72 |
| M14 | Missing database-level constraints | `migrations/000001_initial_state.up.sql` | - |
| M15 | Password migration race condition | `internal/handlers/login.go` | 179-183 |
| M16 | SaveUser concurrent update possibility | `internal/db/sqlite/sqlite.go` | 459-487 |

### Code Quality (3)
| ID | Issue | File | Line |
|----|-------|------|------|
| M17 | Panic usage in production code | Multiple files | - |
| M18 | Missing GoDoc comments | Throughout codebase | - |
| M19 | Duplicate user loading code | `internal/db/sqlite/sqlite.go` | 169-249 |

### Performance (4)
| ID | Issue | File | Line |
|----|-------|------|------|
| M20 | No database query result caching | `internal/db/sqlite/sqlite.go` | - |
| M21 | Global HTTP client race condition | `internal/healthcheck/healthcheck.go` | 12-18 |
| M22 | Conservative server timeouts | `internal/server/server.go` | 101-107 |
| M23 | Base64 encoding allocations in hot path | `internal/db/sqlite/sqlite.go` | Multiple |

---

## LOW SEVERITY ISSUES (18)

### Security (5)
| ID | Issue | File |
|----|-------|------|
| L1 | Timing attack mitigation incomplete | `internal/handlers/login.go:148-163` |
| L2 | No random generation failure checks | `internal/handlers/authn.go:330` |
| L3 | Session expiry not validated per-request | `internal/middlewares/session/session.go:204-206` |
| L4 | Database query context may timeout | Multiple files |
| L5 | Verbose error messages in debug mode | `internal/handlers/login.go` |

### Concurrency (3)
| ID | Issue | File |
|----|-------|------|
| L6 | Salt initialization blocking | `internal/salt/salt.go:54-82` |
| L7 | DebugFlagOverride never set | `internal/config/config.go:27, 59` |
| L8 | Session write count only warns | `internal/middlewares/session/user.go:51, 163-167` |

### Data Access (7)
| ID | Issue | File |
|----|-------|------|
| L9 | Database reopened after migration | `internal/db/sqlite/sqlite.go:63-72` |
| L10 | N+1 query pattern for credentials | `internal/db/sqlite/sqlite.go:192-196` |
| L11 | Missing composite index | `migrations/000002_webauthn.up.sql:20` |
| L12 | GetAllUsers lacks pagination | `internal/db/sqlite/sqlite.go:553-589` |
| L13 | Inconsistent RowsAffected checking | Multiple UPDATE operations |
| L14 | No JSON field sanitization | `internal/db/sqlite/sqlite.go:460-464` |
| L15 | Foreign keys only enabled at runtime | `internal/db/sqlite/sqlite.go:74-77` |

### Code Quality (8)
| ID | Issue | File |
|----|-------|------|
| L16 | Handler package could be split | `internal/handlers/` |
| L17 | Inconsistent log levels | Throughout codebase |
| L18 | context.TODO() in tests | `internal/db/sqlite/sqlite_test.go` |
| L19 | 23 unresolved TODO comments | Throughout codebase |
| L20 | Inconsistent method handling | `internal/handlers/login.go:72-84` |
| L21 | Unclear route patterns | `internal/handlers/env.go:69-71` |
| L22 | Global mutable config state | `internal/config/config.go:20-31` |
| L23 | Repeated admin check logic | `internal/handlers/admin.go` |

---

## Positive Findings

The codebase demonstrates several security and engineering best practices:

### Security Strengths
- **Argon2id password hashing** with proper salt generation
- **Constant-time password comparison** using `subtle.ConstantTimeCompare`
- **100% parameterized SQL queries** - no SQL injection vulnerabilities found
- **Login rate limiting** per-account and per-IP
- **Security headers** properly configured (X-Frame-Options, X-Content-Type-Options)
- **HttpOnly and Secure cookie flags** properly set
- **Foreign key constraints** for data integrity

### Code Quality Strengths
- **Excellent test coverage** - nearly 1:1 test-to-code ratio (~9,300 lines each)
- **Clean package structure** with separation of concerns
- **Dependency injection** via `Env` struct for testability
- **Structured logging** with zerolog
- **Modern Go practices** (Go 1.25, proper error wrapping)
- **Buffer pooling** in renderer to reduce GC pressure

---

## Recommendations by Priority

### Immediate (Critical/High - Address Within 1 Week)
1. **Implement redirect URI validation** - prevents phishing attacks
2. **Fix deadlock in login limiter** - ensure consistent lock ordering
3. **Add synchronization to eventStreamInitialized** - use atomic.Bool
4. **Add locking to AddRule** - prevent race condition
5. **Add CSRF protection** to all state-changing operations
6. **Regenerate session IDs** on authentication
7. **Close HTTP response bodies** in healthcheck
8. **Add capacity limits to TTL caches**

### Short-term (Medium - Address Within 1 Month)
9. Strengthen CSP by removing `unsafe-eval`
10. Change cookies to `SameSite=Strict`
11. Add shutdown mechanisms to background goroutines
12. Configure database connection pool
13. Add transaction support for multi-step operations
14. Implement bounded worker pool for password migrations
15. Add error handling to password migration goroutines
16. Remove panic usage - convert to error returns

### Long-term (Low - Address Within Quarter)
17. Add GoDoc documentation
18. Refactor duplicate user loading code
19. Add database-level constraints
20. Implement user caching to reduce DB load
21. Add pagination to GetAllUsers
22. Standardize logging levels
23. Resolve TODO comments

---

## Testing Recommendations

### Security Testing
- Penetration test focusing on authentication bypass, session management
- Fuzz test all input handlers, especially URL parsing
- Run `gosec` and `staticcheck` for additional findings
- Audit dependencies with `govulncheck`

### Concurrency Testing
```bash
# Run with race detector
go test -race ./...
go build -race
```

### Performance Testing
- Load test login endpoint at 100+ req/s
- Monitor goroutine count, memory usage, DB connections
- Profile with `-memprofile` and `-cpuprofile`
- Test WebAuthn registration flood (DoS scenario)

---

## Appendix: File Reference

### Most Affected Files
| File | Critical | High | Medium | Low |
|------|----------|------|--------|-----|
| `internal/handlers/login.go` | 1 | 1 | 2 | 2 |
| `internal/loginlimit/login_limit.go` | 1 | 1 | 1 | 0 |
| `internal/db/sqlite/sqlite.go` | 0 | 1 | 3 | 5 |
| `internal/trueip/docker_provider.go` | 1 | 1 | 0 | 0 |
| `internal/handlers/authn.go` | 0 | 1 | 1 | 1 |
| `internal/middlewares/session/*.go` | 0 | 1 | 2 | 1 |
| `internal/config/config.go` | 0 | 1 | 1 | 1 |

---

**Report Generated:** 2026-01-04
**Analysis Method:** Automated code review with security, concurrency, and performance focus
**Standards Referenced:** OWASP Top 10, Go Concurrency Best Practices, NIST Password Guidelines
