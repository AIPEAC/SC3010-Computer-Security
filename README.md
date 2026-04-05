# SC3010-Computer-Security
- This is the second part of [SC3010 course project](https://github.com/Shuhui95/SC3010-Case-Study).
- Recreating vulnerability CVE-2017-5638, involving OGNL Expression Injection.

---
## Pre-knowledge
- [How does OGNL injection work?](/_Notes/OGNL-injection.md)
  - Summary of my 3-hour inquiry with **Gemini** on OGNL injection.
---
## Structure

```
SC3010-Computer-Security/
├── simulation/
│   ├── backend/          # Vulnerable Apache Struts2 2.3.28 server (Java/Maven)
│   └── attack-script/    # Exploit script for CVE-2017-5638
│       └── exploit_cve_2017_5638.ps1   # PowerShell (cross-platform)
└── _Notes/               # Background reading
```

See [simulation/attack-script/README.md](simulation/attack-script/README.md) for full setup and usage instructions.

---

## References
- Gemini: https://gemini.com/
