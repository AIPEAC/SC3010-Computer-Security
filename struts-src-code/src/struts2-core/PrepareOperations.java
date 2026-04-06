/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information.
 * This excerpt is derived from Apache Struts 2.3.28.
 */

// ============================================================
// SOURCE: apache/struts @ STRUTS_2_3_28
//   core/src/main/java/org/apache/struts2/dispatcher/ng/PrepareOperations.java
//
// REQUEST HANDOFF TO DISPATCHER
//
// StrutsPrepareAndExecuteFilter.doFilter() calls wrapRequest() here.
// This method immediately delegates to Dispatcher.wrapRequest().
// ============================================================

package org.apache.struts2.dispatcher.ng;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

public class PrepareOperations {

    private org.apache.struts2.dispatcher.Dispatcher dispatcher;

    public PrepareOperations(org.apache.struts2.dispatcher.Dispatcher dispatcher) {
        this.dispatcher = dispatcher;
    }

    /**
     * Wraps multipart requests with Struts' multipart-aware wrapper.
     * This is the direct bridge from the servlet filter to Dispatcher.wrapRequest().
     */
    public HttpServletRequest wrapRequest(HttpServletRequest oldRequest) throws ServletException {
        HttpServletRequest request = oldRequest;
        try {
            request = dispatcher.wrapRequest(request);
            org.apache.struts2.ServletActionContext.setRequest(request);
        } catch (IOException e) {
            throw new ServletException("Could not wrap servlet request with MultipartRequestWrapper!", e);
        }
        return request;
    }
}