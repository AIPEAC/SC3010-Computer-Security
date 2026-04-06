/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information.
 * This excerpt is derived from Apache Struts 2.3.28.
 */

// ============================================================
// SOURCE: apache/struts @ STRUTS_2_3_28
//   core/src/main/java/org/apache/struts2/dispatcher/ng/filter/StrutsPrepareAndExecuteFilter.java
//
// REQUEST ENTRY POINT FOR CVE-2017-5638 WALKTHROUGH
//
// Incoming HTTP requests hit doFilter(). For a multipart upload request,
// the critical handoff is:
//   doFilter()
//     -> prepare.wrapRequest(request)
//     -> Dispatcher.wrapRequest(request)
//     -> new MultiPartRequestWrapper(...)
//     -> multi.parse(request, saveDir)
//     -> JakartaMultiPartRequest.parse(...)
// ============================================================

package org.apache.struts2.dispatcher.ng.filter;

import org.apache.struts2.dispatcher.mapper.ActionMapping;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class StrutsPrepareAndExecuteFilter implements Filter {

    protected org.apache.struts2.dispatcher.ng.PrepareOperations prepare;
    protected org.apache.struts2.dispatcher.ng.ExecuteOperations execute;
    protected java.util.List<java.util.regex.Pattern> excludedPatterns = null;

    /**
     * First Struts2 method that receives the servlet request.
     *
     * Multipart attack path:
     * 1. request enters here
     * 2. prepare.wrapRequest(request) detects multipart/form-data
     * 3. dispatcher creates MultiPartRequestWrapper
     * 4. wrapper immediately calls multi.parse(...)
     */
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest request = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) res;

        try {
            if (excludedPatterns != null && prepare.isUrlExcluded(request, excludedPatterns)) {
                chain.doFilter(request, response);
            } else {
                prepare.setEncodingAndLocale(request, response);
                prepare.createActionContext(request, response);
                prepare.assignDispatcherToThread();

                // ► CALL CHAIN — STEP 1 → STEP 2
                //   StrutsPrepareAndExecuteFilter.doFilter()
                //     → PrepareOperations.wrapRequest()    [see PrepareOperations.java]
                request = prepare.wrapRequest(request);

                ActionMapping mapping = prepare.findActionMapping(request, response, true);
                if (mapping == null) {
                    boolean handled = execute.executeStaticResourceRequest(request, response);
                    if (!handled) {
                        chain.doFilter(request, response);
                    }
                } else {
                    execute.executeAction(request, response, mapping);
                }
            }
        } finally {
            prepare.cleanupRequest(request);
        }
    }
}