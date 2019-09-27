/*
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2014 ForgeRock AS.
 * Portions copyright 2019 Open Source Solution Technology Corporation
 */

package org.forgerock.openam.scripting;

import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import javax.script.ScriptException;

import org.testng.annotations.Test;

import static org.testng.Assert.*;

public class GroovySandboxTest extends AbstractSandboxTest {
    @Override
    protected ScriptEngine getEngine(final ScriptEngineManager manager) {
        return manager.getEngineByName(SupportedScriptingLanguage.GROOVY_ENGINE_NAME);
    }

    @Test
    public void forLoopTest() {
        // Test for Groovy Sandbox Issue #16
        // - Infinite loop when trying to write a for-loop
        //   https://github.com/jenkinsci/groovy-sandbox/issues/16
        String script = "int j = 0;"
                      + "for (i = 0; i < 3; i++) {"
                      + "  if (j >= 3) {"
                      + "    return -1;"
                      + "  };"
                      + "  j++;"
                      + "};"
                      + "return 0;";
        try {
            int ret = eval(script);
            assertEquals(ret, 0);
        } catch (ScriptException se) {
            fail(se.getMessage());
        }
    }

    @Test
    public void tryCatchExceptionTest() {
        // Test for Groovy Sandbox Issue #17
        // - MissingPropertyException in loop with binding variable
        //   https://github.com/jenkinsci/groovy-sandbox/issues/17
        String script = "try {"
                      + "  throw new Exception();"
                      + "} catch (Exception e) {"
                      + "  e.getMessage();"
                      + "  return 0;"
                      + "}";
        try {
            int ret = eval(script);
            assertEquals(ret, 0);
        } catch (ScriptException se) {
            fail(se.getMessage());
        }
    }
}
