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
//   core/src/main/java/com/opensymphony/xwork2/ActionContext.java
//
// RELEVANT TO CVE-2017-5638 EXPLOIT PAYLOAD:
//   Step 1: #context['com.opensymphony.xwork2.ActionContext.container']
//           -- retrieves the IoC Container from the OGNL context map via CONTAINER key + get()
//   Step 2: #container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)
//           -- calls getContainer() then getInstance() on the Container
// ============================================================

package com.opensymphony.xwork2;

import com.opensymphony.xwork2.inject.Container;
import java.io.Serializable;
import java.util.Map;

public class ActionContext implements Serializable {

    static ThreadLocal<ActionContext> actionContext = new ThreadLocal<ActionContext>();

    /**
     * Key used to store/retrieve the IoC Container in the OGNL context map.
     * The exploit uses:  #context['com.opensymphony.xwork2.ActionContext.container']
     */
    public static final String CONTAINER = "com.opensymphony.xwork2.ActionContext.container";

    private Map<String, Object> context;

    public ActionContext(Map<String, Object> context) {
        this.context = context;
    }

    // --- Thread-local accessors used by Struts2 to hand the context to OGNL ---

    public static void setContext(ActionContext context) {
        actionContext.set(context);
    }

    public static ActionContext getContext() {
        return actionContext.get();
    }

    // --- Generic map interface (get/put) -- OGNL reads the context as a Map ---

    /**
     * Returns a value stored in the context map.
     * The exploit calls:  #context['com.opensymphony.xwork2.ActionContext.container']
     * which resolves to:  context.get(CONTAINER)
     */
    public Object get(String key) {
        return context.get(key);
    }

    public void put(String key, Object value) {
        context.put(key, value);
    }

    // --- Container accessors -- used by exploit step 2 ---

    /**
     * Stores the DI container in the context map under the CONTAINER key.
     */
    public void setContainer(Container cont) {
        put(CONTAINER, cont);
    }

    /**
     * Retrieves the DI container from the context map.
     * Called internally by getInstance().
     */
    public Container getContainer() {
        return (Container) get(CONTAINER);
    }

    /**
     * Delegate to the Container to get an instance of the requested type.
     * The exploit calls:  #container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)
     * to obtain the OgnlUtil singleton so it can clear the OGNL security blacklists.
     */
    public <T> T getInstance(Class<T> type) {
        Container cont = getContainer();
        if (cont != null) {
            return cont.getInstance(type);
        } else {
            throw new XWorkException("Cannot find an initialized container for this request.");
        }
    }
}
