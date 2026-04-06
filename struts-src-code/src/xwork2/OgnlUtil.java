/*
 * Copyright 2002-2006,2009 The Apache Software Foundation.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// ============================================================
// SOURCE: apache/struts @ STRUTS_2_3_28
//   core/src/main/java/com/opensymphony/xwork2/ognl/OgnlUtil.java
//
// RELEVANT TO CVE-2017-5638 EXPLOIT PAYLOAD:
//   Step 3a: #ognlUtil.getExcludedPackageNames().clear()
//            -- clears the package-name blacklist so OGNL can access java.lang.*
//   Step 3b: #ognlUtil.getExcludedClasses().clear()
//            -- clears the class blacklist
//   These two .clear() calls disable Struts2's OGNL sandbox, making step 4 possible.
// ============================================================

package com.opensymphony.xwork2.ognl;

import com.opensymphony.xwork2.XWorkConstants;
import com.opensymphony.xwork2.inject.Container;
import com.opensymphony.xwork2.inject.Inject;
import com.opensymphony.xwork2.util.TextParseUtil;
import com.opensymphony.xwork2.config.ConfigurationException;

import java.util.HashSet;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Utility class that provides common access to the Ognl APIs.
 * The security-relevant fields are the blacklists that the exploit clears.
 *
 * @author Jason Carreira
 */
public class OgnlUtil {

    // --- Security blacklists (the exploit targets these via .clear()) ---

    /**
     * Set of classes that OGNL is not allowed to access.
     * Exploit payload clears this: #ognlUtil.getExcludedClasses().clear()
     */
    private Set<Class<?>> excludedClasses = new HashSet<Class<?>>();

    /**
     * Set of package-name patterns that OGNL is not allowed to access.
     */
    private Set<Pattern> excludedPackageNamePatterns = new HashSet<Pattern>();

    /**
     * Set of package names that OGNL is not allowed to access.
     * Exploit payload clears this: #ognlUtil.getExcludedPackageNames().clear()
     */
    private Set<String> excludedPackageNames = new HashSet<String>();

    private Container container;
    private boolean allowStaticMethodAccess;

    // --- @Inject setters: Struts2 populates these from struts-default.xml config ---

    @Inject(value = XWorkConstants.OGNL_EXCLUDED_CLASSES, required = false)
    public void setExcludedClasses(String commaDelimitedClasses) {
        Set<String> classes = TextParseUtil.commaDelimitedStringToSet(commaDelimitedClasses);
        for (String className : classes) {
            try {
                excludedClasses.add(Class.forName(className));
            } catch (ClassNotFoundException e) {
                throw new ConfigurationException("Cannot load excluded class: " + className, e);
            }
        }
    }

    @Inject(value = XWorkConstants.OGNL_EXCLUDED_PACKAGE_NAME_PATTERNS, required = false)
    public void setExcludedPackageNamePatterns(String commaDelimitedPackagePatterns) {
        Set<String> packagePatterns = TextParseUtil.commaDelimitedStringToSet(commaDelimitedPackagePatterns);
        for (String pattern : packagePatterns) {
            excludedPackageNamePatterns.add(Pattern.compile(pattern));
        }
    }

    @Inject(value = XWorkConstants.OGNL_EXCLUDED_PACKAGE_NAMES, required = false)
    public void setExcludedPackageNames(String commaDelimitedPackageNames) {
        excludedPackageNames = TextParseUtil.commaDelimitedStringToSet(commaDelimitedPackageNames);
    }

    // --- Getters that the exploit calls .clear() on ---

    /**
     * Returns the mutable set of excluded classes.
     * Exploit calls:  #ognlUtil.getExcludedClasses().clear()
     * After this, OGNL can access any class including Runtime, ProcessBuilder, etc.
     */
    public Set<Class<?>> getExcludedClasses() {
        return excludedClasses;
    }

    /**
     * Returns the mutable set of excluded package-name patterns.
     */
    public Set<Pattern> getExcludedPackageNamePatterns() {
        return excludedPackageNamePatterns;
    }

    /**
     * Returns the mutable set of excluded package names.
     * Exploit calls:  #ognlUtil.getExcludedPackageNames().clear()
     */
    public Set<String> getExcludedPackageNames() {
        return excludedPackageNames;
    }

    @Inject
    public void setContainer(Container container) {
        this.container = container;
    }

    @Inject(value = XWorkConstants.ALLOW_STATIC_METHOD_ACCESS, required = false)
    public void setAllowStaticMethodAccess(String allowStaticMethodAccess) {
        this.allowStaticMethodAccess = Boolean.parseBoolean(allowStaticMethodAccess);
    }

    /**
     * Creates the default OGNL evaluation context.
     * The SecurityMemberAccess is initialized here with the excluded-classes/package sets.
     * After the exploit clears those sets, any new context created here will have no restrictions.
     */
    protected java.util.Map createDefaultContext(Object root, ognl.ClassResolver classResolver) {
        ClassResolver resolver = classResolver;
        if (resolver == null) {
            resolver = container.getInstance(
                com.opensymphony.xwork2.ognl.accessor.CompoundRootAccessor.class);
        }

        SecurityMemberAccess memberAccess = new SecurityMemberAccess(allowStaticMethodAccess);
        memberAccess.setExcludedClasses(excludedClasses);
        memberAccess.setExcludedPackageNamePatterns(excludedPackageNamePatterns);
        memberAccess.setExcludedPackageNames(excludedPackageNames);

        return ognl.Ognl.createDefaultContext(root, resolver, null, memberAccess);
    }
}
