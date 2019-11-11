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
 *
 * Portions Copyrighted 2019 OGIS-RI Co., Ltd.
 */

package com.sun.identity.common;

import org.testng.annotations.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.Set;

import static org.testng.Assert.*;

public class CaseInsensitivePropertiesTest {

    @Test
    public void test() throws Exception {
        CaseInsensitiveProperties p = new CaseInsensitiveProperties();
        p.put("One", "une");
        p.put("tWo", "deux");
        assertEquals(p.get("ONE"), "une");
        assertEquals(p.get("TWO"), "deux");
        assertEquals(p.get(new CaseInsensitiveKey("ONE")), "une");
        assertEquals(p.get(new CaseInsensitiveKey("TWO")), "deux");
        assertTrue(p.containsKey("oNE"));
        assertTrue(p.containsKey("Two"));
        assertTrue(p.containsKey(new CaseInsensitiveKey("oNE")));
        assertTrue(p.containsKey(new CaseInsensitiveKey("Two")));
        p.setProperty("oNE", "uno");
        p.setProperty("tWo", "dos");
        assertEquals(p.get("ONE"), "uno");
        assertEquals(p.get("TWO"), "dos");
        assertEquals(p.get(new CaseInsensitiveKey("ONE")), "uno");
        assertEquals(p.get(new CaseInsensitiveKey("TWO")), "dos");
        assertTrue(p.containsKey("One"));
        assertTrue(p.containsKey("tWo"));
        assertTrue(p.containsKey("One"));
        assertTrue(p.containsKey("tWo"));

        ByteArrayOutputStream pOut = new ByteArrayOutputStream();
        p.store(pOut, null);
        System.out.println(pOut.toString());
        ByteArrayInputStream pIn = new ByteArrayInputStream(pOut.toByteArray());
        CaseInsensitiveProperties pp = new CaseInsensitiveProperties();
        pp.load(pIn);
        assertEquals(pp.get("ONE"), "uno");
        assertEquals(pp.get("TWO"), "dos");
        assertEquals(p.get(new CaseInsensitiveKey("ONE")), "uno");
        assertEquals(p.get(new CaseInsensitiveKey("TWO")), "dos");
        
        p.clear();
        assertFalse(p.containsKey("One"));
        assertFalse(p.containsKey("tWo"));
        
        assertEquals(pp.setProperty("one", "xxx"),"uno");
        assertEquals(pp.get("ONE"), "xxx");
        assertEquals(pp.put(new CaseInsensitiveKey("onE"), "une"),"xxx");
        assertEquals(pp.get("ONE"), "une");
        
        Set keySet = pp.keySet();
        assertTrue(keySet.contains("oNE"));
        assertTrue(keySet.contains("tWo"));
        assertTrue(keySet.contains(new CaseInsensitiveKey("ONE")));
        assertTrue(keySet.contains(new CaseInsensitiveKey("TWO")));
        for (Object o: keySet) {
            assertTrue( o instanceof String);
            assertTrue(pp.containsKey((String)o));
        }
        
        assertEquals(pp.remove("OnE"),"une");
        assertFalse(pp.containsKey("one"));
        assertEquals(pp.get("twO"), "dos");
        assertEquals(pp.remove(new CaseInsensitiveKey("Two")), "dos");
        
    }

}
