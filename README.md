# SC3010-Computer-Security
- This is the second part of [SC3010 course project](https://github.com/Shuhui95/SC3010-Case-Study).
- Recreating vulnerability CVE-2017-5638, involving OGNL Expression Injection.
- Third party notice:
  - Copied code from [struts2](https://github.com/apache/struts/) original repository, which is licensed under the [Apache 2.0 License](struts-src-code/LICENSE.txt).

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
└── _notes/               # Background reading
```

See [simulation/README.md](simulation/README.md) for full setup and usage instructions.

---

## References
- Gemini: https://gemini.com/
