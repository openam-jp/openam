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
 * Copyright 2026 3A Systems, LLC.
 * Portions copyright 2026 OSSTech Corporation
 */
package com.sun.identity.saml.common;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.testng.annotations.Test;

public class SAMLUtilsTest {

    private static final Pattern HIDDEN_INPUT =
            Pattern.compile("<INPUT TYPE=\"HIDDEN\" NAME=\"([^\"<>]*)\" VALUE=\"([^\"<>]*)\">");

    private static final Pattern CHAR_REF = Pattern.compile("&(#x[0-9a-fA-F]+|#[0-9]+|[a-zA-Z]+);");

    /**
     * postYN() only checks host, port and path of the target, so the query string
     * is attacker-influenced and must not be able to close the ACTION attribute.
     */
    @Test
    public void postToTargetEscapesTargetUrlInFormAction() throws Exception {
        String target = "https://sp.example.com/acs?next=\"><script>alert(1)</script><a href=\"";
        StringWriter html = new StringWriter();

        SAMLUtils.postToTarget(null, new PrintWriter(html), Collections.emptyList(), target,
                Collections.emptyMap());

        String out = html.toString();
        assertThat(out).doesNotContain("<script>");
        Matcher action = Pattern.compile("<FORM METHOD=\"POST\" ACTION=\"([^\"<>]*)\">").matcher(out);
        assertThat(action.find()).isTrue();
        assertThat(decode(action.group(1))).isEqualTo(target);
    }

    /**
     * Attribute names and values come verbatim from the partner IdP's assertion, so they are
     * escaped in full: markup must stay inert and an '&' must reach the target unchanged.
     */
    @Test
    public void postToTargetEscapesAttributeNamesAndValues() throws Exception {
        Map<String, String> attrs = new LinkedHashMap<>();
        attrs.put("x\"<y", "<script>alert(1)</script>");
        attrs.put("amp", "a&amp;b");
        attrs.put("q", "\" onfocus=\"alert(1)\" autofocus x=\"");
        StringWriter html = new StringWriter();

        SAMLUtils.postToTarget(null, new PrintWriter(html), Collections.emptyList(),
                "https://sp.example.com/acs", attrs);

        String out = html.toString();
        assertThat(out).doesNotContain("<script>");
        assertThat(out).doesNotContain("onfocus=");

        // Every hidden input must parse as exactly one NAME and one VALUE attribute,
        // and decode back to what was posted.
        Map<String, String> posted = new LinkedHashMap<>();
        Matcher input = HIDDEN_INPUT.matcher(out);
        while (input.find()) {
            posted.put(decode(input.group(1)), decode(input.group(2)));
        }
        Map<String, String> expected = new LinkedHashMap<>(attrs);
        expected.put(SAMLConstants.POST_ATTR_NAMES, "x\"<y:amp:q");
        assertThat(posted).isEqualTo(expected);
    }

    /** Decodes character references as a browser does inside an attribute value. */
    private static String decode(String s) {
        Matcher m = CHAR_REF.matcher(s);
        StringBuffer sb = new StringBuffer();
        while (m.find()) {
            String ref = m.group(1);
            String ch;
            if (ref.startsWith("#x")) {
                ch = new String(Character.toChars(Integer.parseInt(ref.substring(2), 16)));
            } else if (ref.startsWith("#")) {
                ch = new String(Character.toChars(Integer.parseInt(ref.substring(1))));
            } else if ("quot".equals(ref)) {
                ch = "\"";
            } else if ("amp".equals(ref)) {
                ch = "&";
            } else if ("lt".equals(ref)) {
                ch = "<";
            } else if ("gt".equals(ref)) {
                ch = ">";
            } else if ("apos".equals(ref)) {
                ch = "'";
            } else {
                throw new AssertionError("Unexpected entity: &" + ref + ";");
            }
            m.appendReplacement(sb, Matcher.quoteReplacement(ch));
        }
        m.appendTail(sb);
        return sb.toString();
    }
}
