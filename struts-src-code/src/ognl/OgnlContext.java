// --------------------------------------------------------------------------
// Copyright (c) 1998-2004, Drew Davidson and Luke Blanshard
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// Redistributions of source code must retain the above copyright notice,
// this list of conditions and the following disclaimer.
// Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution.
// Neither the name of the Drew Davidson nor the names of its contributors
// may be used to endorse or promote products derived from this software
// without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
// FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
// COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
// INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
// BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
// OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
// AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
// --------------------------------------------------------------------------

// ============================================================
// SOURCE: jkuhnert/ognl @ OGNL_3_0_13
//   src/java/ognl/OgnlContext.java
//
// RELEVANT TO CVE-2017-5638 EXPLOIT PAYLOAD:
//   Step 4: #context.setMemberAccess(@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)
//           -- replaces the restricted SecurityMemberAccess (which normally
//              blocks access to private fields and dangerous classes) with
//              DefaultMemberAccess, which allows unrestricted reflection.
//           -- @ognl.OgnlContext@DEFAULT_MEMBER_ACCESS is a static field here.
//           -- After this, Runtime.getRuntime().exec(...) becomes accessible.
// ============================================================

package ognl;

import java.util.HashMap;
import java.util.Map;

/**
 * This class defines the execution context for an OGNL expression.
 *
 * @author Luke Blanshard (blanshlu@netscape.net)
 * @author Drew Davidson (drew@ognl.org)
 */
public class OgnlContext implements Map {

    public static final String MEMBER_ACCESS_CONTEXT_KEY = "_memberAccess";

    /**
     * The default (unrestricted) MemberAccess instance.
     * The exploit references this as:  @ognl.OgnlContext@DEFAULT_MEMBER_ACCESS
     *
     * DefaultMemberAccess grants access to all fields and methods regardless of
     * visibility, bypassing any blacklist checks.
     */
    public static final MemberAccess DEFAULT_MEMBER_ACCESS = new DefaultMemberAccess(false);

    private MemberAccess _memberAccess = DEFAULT_MEMBER_ACCESS;

    // --- Constructor ---

    public OgnlContext(ClassResolver classResolver, TypeConverter typeConverter, MemberAccess memberAccess) {
        // simplified: only track memberAccess for exploit relevance
        if (memberAccess != null) {
            this._memberAccess = memberAccess;
        }
    }

    // --- MemberAccess accessor (the exploit calls setMemberAccess) ---

    /**
     * Sets the MemberAccess policy for this context.
     * The exploit calls:
     *   #context.setMemberAccess(@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)
     * replacing Struts2''s SecurityMemberAccess (restrictive) with the default
     * unrestricted one, so that subsequent OGNL expressions may call any method.
     */
    public void setMemberAccess(MemberAccess value) {
        if (value == null) { throw new IllegalArgumentException("cannot set MemberAccess to null"); }
        _memberAccess = value;
    }

    public MemberAccess getMemberAccess() {
        return _memberAccess;
    }

    // --- Map.put() -- OGNL uses this when evaluating "#context.setMemberAccess(...)" ---

    public Object put(Object key, Object value) {
        if (MEMBER_ACCESS_CONTEXT_KEY.equals(key)) {
            // OGNL resolves setMemberAccess via the reserved-key path in the full implementation
            setMemberAccess((MemberAccess) value);
            return _memberAccess;
        }
        // other keys omitted (not relevant to exploit)
        return null;
    }

    // --- Stub Map interface methods (not relevant to exploit) ---
    public int size()                          { return 0; }
    public boolean isEmpty()                   { return true; }
    public boolean containsKey(Object key)     { return false; }
    public boolean containsValue(Object value) { return false; }
    public Object get(Object key)              { return null; }
    public Object remove(Object key)           { return null; }
    public void putAll(Map t)                  {}
    public void clear()                        {}
    public java.util.Set keySet()              { return new java.util.HashSet(); }
    public java.util.Collection values()       { return new java.util.ArrayList(); }
    public java.util.Set entrySet()            { return new java.util.HashSet(); }
}
