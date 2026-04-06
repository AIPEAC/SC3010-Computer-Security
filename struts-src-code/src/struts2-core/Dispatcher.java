/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information.
 * This excerpt is derived from Apache Struts 2.3.28.
 */

// ============================================================
// SOURCE: apache/struts @ STRUTS_2_3_28
//   core/src/main/java/org/apache/struts2/dispatcher/Dispatcher.java
//
// MULTIPART DECISION POINT
//
// Dispatcher.wrapRequest() checks request.getContentType().
// If it contains "multipart/form-data", Struts instantiates
// MultiPartRequestWrapper, which immediately parses the request.
// ============================================================

package org.apache.struts2.dispatcher;

import com.opensymphony.xwork2.LocaleProvider;
import com.opensymphony.xwork2.inject.Container;
import org.apache.struts2.dispatcher.multipart.MultiPartRequest;
import org.apache.struts2.dispatcher.multipart.MultiPartRequestWrapper;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.Set;

public class Dispatcher {

    private String multipartHandlerName;
    private String multipartSaveDir = "";
    private boolean disableRequestAttributeValueStackLookup;
    protected javax.servlet.ServletContext servletContext;

    /**
     * Multipart detection happens here.
     *
     * If Content-Type contains "multipart/form-data", Struts creates a
     * MultiPartRequestWrapper, which immediately invokes multi.parse(request, saveDir).
     */
    public HttpServletRequest wrapRequest(HttpServletRequest request) throws IOException {
        if (request instanceof StrutsRequestWrapper) {
            return request;
        }

        String contentType = request.getContentType();
        if (contentType != null && contentType.contains("multipart/form-data")) {
            MultiPartRequest mpr = getMultiPartRequest();
            LocaleProvider provider = getContainer().getInstance(LocaleProvider.class);
            request = new MultiPartRequestWrapper(
                    mpr,
                    request,
                    getSaveDir(),
                    provider,
                    disableRequestAttributeValueStackLookup);
        } else {
            request = new StrutsRequestWrapper(request, disableRequestAttributeValueStackLookup);
        }

        return request;
    }

    /**
     * Creates a fresh multipart parser instance for this request.
     * In the Equifax-style path this resolves to JakartaMultiPartRequest.
     */
    protected MultiPartRequest getMultiPartRequest() {
        MultiPartRequest mpr = null;
        Set<String> multiNames = getContainer().getInstanceNames(MultiPartRequest.class);
        for (String multiName : multiNames) {
            if (multiName.equals(multipartHandlerName)) {
                mpr = getContainer().getInstance(MultiPartRequest.class, multiName);
            }
        }
        if (mpr == null) {
            mpr = getContainer().getInstance(MultiPartRequest.class);
        }
        return mpr;
    }

    private String getSaveDir() {
        String saveDir = multipartSaveDir.trim();
        if (saveDir.equals("")) {
            java.io.File tempdir = (java.io.File) servletContext.getAttribute("javax.servlet.context.tempdir");
            if (tempdir != null) {
                saveDir = tempdir.toString();
            }
        }
        return saveDir;
    }

    public Container getContainer() {
        throw new UnsupportedOperationException("Trimmed reference excerpt");
    }
}