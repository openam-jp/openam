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
 * Copyright 2015 ForgeRock AS.
 *
 * Portions Copyrighted 2019 OGIS-RI Co., Ltd.
 */
package com.iplanet.dpro.session;

import static org.mockito.BDDMockito.*;
import com.iplanet.services.naming.SessionIDCorrector;
import com.iplanet.services.naming.WebtopNamingQuery;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

public class DynamicSessionIDExtensionsTest {

    private SessionIDCorrector mockCorrector;
    private WebtopNamingQuery mockQuery;
    private SessionIDExtensions mockDelegate;
    private DynamicSessionIDExtensions dynamic;

    @BeforeMethod
    public void setup() {
        mockQuery = mock(WebtopNamingQuery.class);
        mockCorrector = mock(SessionIDCorrector.class);
        given(mockQuery.getSessionIDCorrector()).willReturn(mockCorrector);

        mockDelegate = mock(SessionIDExtensions.class);

        dynamic = new DynamicSessionIDExtensions(mockQuery, mockDelegate);
    }

    @Test
    public void shouldUseSessionIDCorrectorForPrimaryID() {
        dynamic.getPrimaryID();
        verify(mockCorrector).translatePrimaryID(nullable(String.class), nullable(String.class));
    }

    @Test
    public void shouldUseSessionIDCorrectorForSiteID() {
        dynamic.getSiteID();
        verify(mockCorrector).translateSiteID(nullable(String.class), nullable(String.class));
    }

    @Test
    public void shouldReturnDelegateIfSessionIDCorrectorNotInitialised() {
        given(mockQuery.getSessionIDCorrector()).willReturn(null);
        dynamic.getPrimaryID();
        verify(mockDelegate).getPrimaryID();
    }
}