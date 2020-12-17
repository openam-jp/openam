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
 * Copyright 2020 Open Source Solution Technology Corporation
 * Portions copyright 2020 OGIS-RI Co., Ltd.
 */

package jp.co.osstech.openam.shared.cookie;

import static org.fest.assertions.Assertions.*;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.anyString;
import static org.mockito.Mockito.mock;

import javax.servlet.http.HttpServletRequest;

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

public class SameSiteTest {

    private HttpServletRequest mockHttpServletRequest = mock(HttpServletRequest.class);

    @DataProvider(name = "userAgentTest")
    public Object[][] getUserAgentTestCases() {
        return new Object[][]{
            // Microsoft Edge 44 on Winsows 10 -> SameSite compatible
            {"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36 Edge/18.18362", true},
            // Mozilla Firefox 72 on Winsows 10 -> SameSite compatible
            {"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:72.0) Gecko/20100101 Firefox/72.0", true},
            // Google Chrome 79 on Winsows 10 -> SameSite compatible
            {"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.130 Safari/537.36", true},
            // Safari on iOS13 -> SameSite compatible
            {"Mozilla/5.0 (iPhone; CPU iPhone OS 13_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0 Mobile/15E148 Safari/604.1", true},
            // Safari on macOS Catalina -> SameSite compatible
            {"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0 Safari/605.1.15", true},
            // Google Chrome 77 on macOS Mojave -> SameSite compatible
            {"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3864.0 Safari/537.36", true},
            // Safari on iOS12 -> SameSite incompatible
            {"Mozilla/5.0 (iPhone; CPU iPhone OS 12_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0 Mobile/15E148 Safari/604.1", false},
            // Safari on macOS Mojave -> SameSite incompatible
            {"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.1.2 Safari/605.1.15", false},
        };
    }

    @Test(dataProvider = "userAgentTest")
    public void testSameSiteSuport(String userAgent, boolean result) {
        given(mockHttpServletRequest.getHeader(anyString())).willReturn(userAgent);
        assertThat(SameSite.isSupportedClient(mockHttpServletRequest)).isEqualTo(result);
    }
}
