# SC3010-Computer-Security
- This is the second part of [SC3010 course project](https://github.com/Shuhui95/SC3010-Case-Study).
- Recreating vulnerability CVE-2017-5638, involving OGNL Expression Injection.

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

Source references:
- [apache/struts @ STRUTS\_2\_3\_28](https://github.com/apache/struts/tree/STRUTS_2_3_28) — Struts2 core and XWork
- [jkuhnert/ognl](https://github.com/jkuhnert/ognl) — OGNL 3.0.x

---
## Pre-knowledge
- [How does OGNL injection work?](_note/OGNL-injection-introduction.md)
  - Summary of my 3-hour inquiry with **Gemini** on OGNL injection.
---
## Structure

```
SC3010-Computer-Security/
├── simulation/
│   ├── backend/          # Vulnerable Apache Struts2 2.3.28 server (Java/Maven)
│   └── attack-script/    # Exploit script for CVE-2017-5638
│       └── exploit_cve_2017_5638.ps1   # PowerShell (cross-platform)
├── struts-src-code/          # Apache Struts2 reference source + legal notices
│   ├── licenses/             # LICENSE, NOTICE, and component licenses
│   └── src/
│       ├── struts2-core/     # JakartaMultiPartRequest.java (vulnerable class)
│       ├── xwork2/           # ActionContext.java, OgnlUtil.java
│       └── ognl/             # OgnlContext.java
└── _notes/               # Background reading
```

See [simulation/README.md](simulation/README.md) for full setup and usage instructions.

---

## References
- Gemini: https://gemini.com/
- Struts2 repo on GitHub, branch 2.3.28: https://github.com/apache/struts/tree/STRUTS_2_3_28
