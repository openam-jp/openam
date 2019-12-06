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
 * Copyright 2019 Open Source Solution Technology Corporation
 */
package jp.co.osstech.openam.core.rest.devices.services.webauthn;

import java.util.HashMap;
import java.util.Map;

import javax.inject.Singleton;

import com.iplanet.sso.SSOException;
import com.sun.identity.common.ShutdownManager;
import com.sun.identity.sm.SMSException;
import com.sun.identity.sm.ServiceConfigManager;
import org.forgerock.openam.core.rest.devices.services.DeviceServiceFactory;
import org.forgerock.util.thread.listener.ShutdownListener;

/**
 * Produces AuthenticatorWebAuthnService's for a specific realm.
 */
@Singleton
public class AuthenticatorWebAuthnServiceFactory implements DeviceServiceFactory<AuthenticatorWebAuthnService> {

    /** Name of this factory for Guice purposes. */
    public static final String FACTORY_NAME = "AuthenticatorWebAuthnServiceFactory";

    private final Map<String, AuthenticatorWebAuthnService> serviceSettingsMap = new HashMap<>();

    /**
     * Default constructor.
     */
    public AuthenticatorWebAuthnServiceFactory() {
        ShutdownManager shutdownManager = ShutdownManager.getInstance();
        shutdownManager.addShutdownListener(new ShutdownListener() {
            @Override
            public void shutdown() {
                for (String realm : serviceSettingsMap.keySet()) {
                    AuthenticatorWebAuthnService service = serviceSettingsMap.get(realm);
                    service.close();
                }
            }
        });
    }

    @Override
    public AuthenticatorWebAuthnService create(ServiceConfigManager serviceConfigManager, String realm)
            throws SSOException, SMSException {
        AuthenticatorWebAuthnService newService = new AuthenticatorWebAuthnService(serviceConfigManager, realm);
        AuthenticatorWebAuthnService oldService = serviceSettingsMap.put(realm, newService);
        if (oldService != null) {
            oldService.close();
        }
        return newService;
    }

}
