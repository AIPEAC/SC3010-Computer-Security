/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information.
 * This excerpt is derived from Apache Struts 2.3.28.
 */

// ============================================================
// SOURCE: apache/struts @ STRUTS_2_3_28
//   core/src/main/java/org/apache/struts2/dispatcher/multipart/MultiPartRequestWrapper.java
//
// PARSER INVOCATION POINT
//
// This constructor is where Struts actually calls:
//   multi.parse(request, saveDir)
// If the parser implementation is JakartaMultiPartRequest,
// execution enters JakartaMultiPartRequest.parse().
// ============================================================

package org.apache.struts2.dispatcher.multipart;

import com.opensymphony.xwork2.LocaleProvider;
import com.opensymphony.xwork2.util.LocalizedTextUtil;
import org.apache.struts2.dispatcher.StrutsRequestWrapper;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Locale;

public class MultiPartRequestWrapper extends StrutsRequestWrapper {

    private Collection<String> errors;
    private MultiPartRequest multi;
    private Locale defaultLocale = Locale.ENGLISH;

    /**
     * The key constructor in the exploit path.
     * Instantiating this wrapper immediately triggers multipart parsing.
     */
    public MultiPartRequestWrapper(
            MultiPartRequest multiPartRequest,
            HttpServletRequest request,
            String saveDir,
            LocaleProvider provider,
            boolean disableRequestAttributeValueStackLookup) {
        super(request, disableRequestAttributeValueStackLookup);
        errors = new ArrayList<String>();
        multi = multiPartRequest;
        defaultLocale = provider.getLocale();
        setLocale(request);
        try {
            // This line is the direct jump into JakartaMultiPartRequest.parse().
            multi.parse(request, saveDir);
            for (String error : multi.getErrors()) {
                addError(error);
            }
        } catch (IOException e) {
            addError(buildErrorMessage(e, new Object[] {e.getMessage()}));
        }
    }

    protected void setLocale(HttpServletRequest request) {
        if (defaultLocale == null) {
            defaultLocale = request.getLocale();
        }
    }

    protected String buildErrorMessage(Throwable e, Object[] args) {
        String errorKey = "struts.messages.upload.error." + e.getClass().getSimpleName();
        return LocalizedTextUtil.findText(this.getClass(), errorKey, defaultLocale, e.getMessage(), args);
    }

    protected void addError(String anErrorMessage) {
        if (!errors.contains(anErrorMessage)) {
            errors.add(anErrorMessage);
        }
    }
}