/*
 * $Id$
 *
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

// ============================================================
// SOURCE: apache/struts @ STRUTS_2_3_28
//   core/src/main/java/org/apache/struts2/dispatcher/multipart/JakartaMultiPartRequest.java
//
// VULNERABLE CODE -- CVE-2017-5638 ENTRY POINT
//
// The vulnerability is in parse() -> buildErrorMessage():
//   1. A multipart request with a malicious Content-Type header arrives.
//   2. The Commons FileUpload library throws an exception whose message
//      contains the raw Content-Type value.
//   3. buildErrorMessage() passes that message to LocalizedTextUtil.findText(),
//      which evaluates OGNL expressions embedded in the string.
//   4. Because the Content-Type value was attacker-controlled, arbitrary OGNL
//      (and therefore arbitrary Java code) executes on the server.
//
// Attack timeline: exploit first used ~May 13, 2017 in Equifax breach.
// ============================================================

package org.apache.struts2.dispatcher.multipart;

import com.opensymphony.xwork2.LocaleProvider;
import com.opensymphony.xwork2.inject.Inject;
import com.opensymphony.xwork2.util.LocalizedTextUtil;
import com.opensymphony.xwork2.util.logging.Logger;
import com.opensymphony.xwork2.util.logging.LoggerFactory;
import org.apache.commons.fileupload.FileItem;
import org.apache.commons.fileupload.FileUploadBase;
import org.apache.commons.fileupload.FileUploadException;
import org.apache.commons.fileupload.RequestContext;
import org.apache.commons.fileupload.disk.DiskFileItemFactory;
import org.apache.commons.fileupload.servlet.ServletFileUpload;
import org.apache.struts2.StrutsConstants;

import javax.servlet.http.HttpServletRequest;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Multipart form data request adapter for Jakarta Commons Fileupload package.
 *
 * VULNERABLE: The Content-Type header from the HTTP request is passed through
 * an exception message into OGNL evaluation without sanitization.
 */
public class JakartaMultiPartRequest implements MultiPartRequest {

    static final Logger LOG = LoggerFactory.getLogger(JakartaMultiPartRequest.class);

    protected List<String> errors = new ArrayList<String>();
    protected long maxSize;
    private Locale defaultLocale = Locale.ENGLISH;

    @Inject(StrutsConstants.STRUTS_MULTIPART_MAXSIZE)
    public void setMaxSize(String maxSize) {
        this.maxSize = Long.parseLong(maxSize);
    }

    @Inject
    public void setLocaleProvider(LocaleProvider provider) {
        defaultLocale = provider.getLocale();
    }

    /**
     * VULNERABLE METHOD -- entry point for CVE-2017-5638.
     *
     * When Commons FileUpload cannot parse the Content-Type (because the
     * attacker replaced it with an OGNL payload), it throws an exception.
     * The catch block here calls buildErrorMessage(e, ...) -- which triggers
     * OGNL evaluation of the attacker-supplied Content-Type string.
     */
    public void parse(HttpServletRequest request, String saveDir) throws IOException {
        try {
            setLocale(request);
            processUpload(request, saveDir);
        } catch (FileUploadBase.SizeLimitExceededException e) {
            if (LOG.isWarnEnabled()) {
                LOG.warn("Request exceeded size limit!", e);
            }
            // VULNERABLE: e.getMessage() may contain the attacker-supplied Content-Type
            String errorMessage = buildErrorMessage(e, new Object[]{e.getPermittedSize(), e.getActualSize()});
            if (!errors.contains(errorMessage)) {
                errors.add(errorMessage);
            }
        } catch (Exception e) {
            if (LOG.isWarnEnabled()) {
                LOG.warn("Unable to parse request", e);
            }
            // VULNERABLE: e.getMessage() contains the raw Content-Type header value
            // which is passed to LocalizedTextUtil.findText() -> OGNL evaluation
            String errorMessage = buildErrorMessage(e, new Object[]{});
            if (!errors.contains(errorMessage)) {
                errors.add(errorMessage);
            }
        }
    }

    protected void setLocale(HttpServletRequest request) {
        if (defaultLocale == null) {
            defaultLocale = request.getLocale();
        }
    }

    /**
     * VULNERABLE METHOD -- builds an error message from an exception.
     *
     * Calls LocalizedTextUtil.findText(), which internally calls
     * TextParseUtil.translateVariables(), which evaluates any %{...}
     * OGNL expressions found in the message string.
     *
     * Because the message originates from the exception thrown by
     * Commons FileUpload when it rejects the Content-Type header,
     * and the Content-Type was attacker-controlled, this evaluates
     * arbitrary OGNL as the server process.
     */
    protected String buildErrorMessage(Throwable e, Object[] args) {
        String errorKey = "struts.messages.upload.error." + e.getClass().getSimpleName();
        if (LOG.isDebugEnabled()) {
            LOG.debug("Preparing error message for key: [#0]", errorKey);
        }
        // findText falls back to e.getMessage() when the key is not found,
        // then passes that string through OGNL variable translation.
        return LocalizedTextUtil.findText(this.getClass(), errorKey, defaultLocale, e.getMessage(), args);
    }

    protected void processUpload(HttpServletRequest request, String saveDir)
            throws FileUploadException, UnsupportedEncodingException {
        for (FileItem item : parseRequest(request, saveDir)) {
            // file/form-field processing -- not relevant to the exploit
        }
    }

    protected List<FileItem> parseRequest(HttpServletRequest servletRequest, String saveDir)
            throws FileUploadException {
        DiskFileItemFactory fac = new DiskFileItemFactory();
        fac.setSizeThreshold(0);
        if (saveDir != null) {
            fac.setRepository(new File(saveDir));
        }
        ServletFileUpload upload = new ServletFileUpload(fac);
        upload.setSizeMax(maxSize);
        // createRequestContext wraps the servlet request so Commons FileUpload can read
        // the Content-Type.  That Content-Type is what the attacker poisons.
        return upload.parseRequest(createRequestContext(servletRequest));
    }

    /**
     * Wraps the HttpServletRequest into a Commons FileUpload RequestContext.
     * getContentType() here returns req.getContentType() -- the attacker-controlled value.
     */
    protected RequestContext createRequestContext(final HttpServletRequest req) {
        return new RequestContext() {
            public String getCharacterEncoding() { return req.getCharacterEncoding(); }
            public String getContentType()       { return req.getContentType(); }
            public int    getContentLength()     { return req.getContentLength(); }
            public InputStream getInputStream() throws IOException {
                InputStream in = req.getInputStream();
                if (in == null) throw new IOException("Missing content in the request");
                return req.getInputStream();
            }
        };
    }
}
