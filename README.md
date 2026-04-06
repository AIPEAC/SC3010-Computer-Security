# SC3010-Computer-Security — CVE-2017-5638 Attack Recreation

This repository is part of the [SC3010 Computer Security course project](https://github.com/Shuhui95/SC3010-Case-Study).  
It recreates **CVE-2017-5638**, a critical Remote Code Execution vulnerability in Apache Struts 2 (versions 2.3.5–2.3.31 and 2.5–2.5.10), famously exploited in the **2017 Equifax data breach** to exfiltrate personal records of roughly 147 million people.

The vulnerability arises from a single design flaw: when Apache Struts fails to parse a `multipart/form-data` upload request, it builds an error message by embedding the raw `Content-Type` header — without sanitizing it — into a string that is then passed through the OGNL expression evaluator. An attacker who puts an OGNL expression inside the `Content-Type` header therefore gets it executed server-side as the Tomcat process user.

This repo contains:
- A working **vulnerable Java/Maven server** (Struts2 2.3.28) with a file-upload endpoint.
- A **PowerShell exploit script** that demonstrates the full injection → RCE chain.
- Annotated **reference source files** from Apache Struts 2.3.28 mapping each step of the call chain.

---

## Background Knowledge
- [How does OGNL injection work?](_note/OGNL-injection-introduction.md)

---
## Exploit Simulation
- See [attack-recreate/attack-script/README.md](attack-recreate/attack-script/README.md) for setup and usage instructions.

---

## Attack State Machine Diagram

The diagram below shows each decision branch in the Struts2 request pipeline. The red path is the one the attacker forces; grey `→ ...` branches are safe paths that don't apply during the exploit.

```mermaid
flowchart TD
    Start([Attacker sends HTTP POST /upload.action<br/>Content-Type: &#37;&#123;OGNL_PAYLOAD&#125;.multipart/form-data])
    Start --> PIPE

    PIPE["<b>Struts2 filter → wrap → parse pipeline</b><br/>doFilter() → PrepareOperations.wrapRequest()<br/>→ Dispatcher.wrapRequest() → new MultiPartRequestWrapper()"]
    PIPE --> D_CT{"Content-Type contains<br/>&quot;multipart/form-data&quot;?"}
    D_CT -- "No → normal request ..." --> OUT_NORM([non-upload path ...])
    D_CT -- "Yes (attacker appends<br/>.multipart/form-data to payload)" --> PARSE

    PARSE[/"<b>JakartaMultiPartRequest.parse()</b><br/>→ Commons FileUpload.parseRequest()"/]
    PARSE --> D_VALID{"FileUpload can parse<br/>Content-Type?"}
    D_VALID -- "Yes → normal file upload ..." --> OUT_OK([files extracted, action executes ...])
    D_VALID -- "No — malformed Content-Type<br/>throws InvalidContentTypeException<br/>(message = raw Content-Type string)" --> CATCH

    CATCH["parse() catch block<br/>calls buildErrorMessage(e, &#123;&#125;)"]
    CATCH --> FIND

    FIND[/"<b>buildErrorMessage()</b><br/>→ LocalizedTextUtil.findText(class, errorKey, locale, e.getMessage(), args)"/]
    FIND --> D_KEY{"Resource bundle has key<br/>struts.messages.upload.error.*?"}
    D_KEY -- "Yes → safe localised message ..." --> OUT_SAFE([error displayed safely ...])
    D_KEY -- "No — falls back to<br/>e.getMessage() as the default<br/>(attacker's raw Content-Type)" --> TRANSLATE

    TRANSLATE["TextParseUtil.translateVariables()<br/>scans string for &#37;&#123;...&#125; expressions"]
    TRANSLATE --> D_OGNL{"String contains<br/>&#37;&#123;...&#125; OGNL expression?"}
    D_OGNL -- "No → plain error string ..." --> OUT_PLAIN([safe error message ...])
    D_OGNL -- "Yes — evaluates OGNL<br/>inside attacker content" --> SANDBOX

    SANDBOX[/"<b>OGNL sandbox bypass</b><br/>#ognlUtil.getExcludedClasses().clear()<br/>#ognlUtil.getExcludedPackageNames().clear()"/]
    SANDBOX --> ACCESS

    ACCESS[/"<b>Unrestricted reflection</b><br/>#context.setMemberAccess(DEFAULT_MEMBER_ACCESS)"/]
    ACCESS --> RCE

    RCE[/"<b>RCE</b><br/>Runtime.getRuntime().exec(cmd)"/]
    RCE --> Done([Command executed as Tomcat process user])

    style Start fill:#d32f2f,color:#fff
    style Done fill:#d32f2f,color:#fff
    style OUT_NORM fill:#9e9e9e,color:#fff
    style OUT_OK fill:#9e9e9e,color:#fff
    style OUT_SAFE fill:#9e9e9e,color:#fff
    style OUT_PLAIN fill:#9e9e9e,color:#fff
    style SANDBOX fill:#b71c1c,color:#fff
    style ACCESS fill:#b71c1c,color:#fff
    style RCE fill:#b71c1c,color:#fff
    style CATCH fill:#e65100,color:#fff
    style TRANSLATE fill:#e65100,color:#fff
```

For the full state-machine with branch explanations, see [diagrams/cve-2017-5638-state-machine.md](diagrams/cve-2017-5638-state-machine.md).  
For a sequence diagram view and annotated OGNL payload breakdown, see [diagrams/cve-2017-5638-attack-chain.md](diagrams/cve-2017-5638-attack-chain.md).

---

## Repository Structure

```
SC3010-Computer-Security/
├── attack-recreate/
│   ├── backend/          # Vulnerable Apache Struts2 2.3.28 server (Java/Maven)
│   └── attack-script/    # Exploit script for CVE-2017-5638
│       └── exploit_cve_2017_5638.ps1   # PowerShell (cross-platform)
├── struts-src-code/          # Apache Struts2 reference source + legal notices
│   ├── licenses/             # LICENSE, NOTICE, and component licenses
│   └── src/
│       ├── struts2-core/     # Request pipeline classes + vulnerable JakartaMultiPartRequest
│       ├── xwork2/           # ActionContext.java, OgnlUtil.java
│       └── ognl/             # OgnlContext.java
├── diagrams/                 # State-machine + sequence diagrams, annotated OGNL payload
└── _notes/                   # Background reading
```

---

## Third-Party Software Notices

This repository reproduces portions of **Apache Struts 2.3.28** source code for academic security research purposes.

> Apache Struts is Copyright © 2000–2016 The Apache Software Foundation.  
> Licensed under the **Apache License, Version 2.0**.  
> A copy of the license is available at [`struts-src-code/licenses/LICENSE.txt`](struts-src-code/licenses/LICENSE.txt).  
> The full attribution notice required by the Apache License is in [`struts-src-code/licenses/NOTICE.txt`](struts-src-code/licenses/NOTICE.txt).

Apache Struts 2 bundles additional third-party components, each governed by their own license:

| Component | License file |
|-----------|--------------|
| OGNL (Object-Graph Navigation Library) | [`struts-src-code/licenses/OGNL-LICENSE.txt`](struts-src-code/licenses/OGNL-LICENSE.txt) |
| XWork | [`struts-src-code/licenses/XWORK-LICENSE.txt`](struts-src-code/licenses/XWORK-LICENSE.txt) |
| FreeMarker | [`struts-src-code/licenses/FREEMARKER-LICENSE.txt`](struts-src-code/licenses/FREEMARKER-LICENSE.txt) |

---

## Source References:
- [apache/struts @ STRUTS\_2\_3\_28](https://github.com/apache/struts/tree/STRUTS_2_3_28) — Struts2 core and XWork
- [jkuhnert/ognl](https://github.com/jkuhnert/ognl) — OGNL 3.0.x
- [Gemini](https://gemini.com/) — Consultation on general OGNL languages.
