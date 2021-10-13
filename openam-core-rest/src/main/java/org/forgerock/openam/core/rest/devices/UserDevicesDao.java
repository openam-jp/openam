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
 * Copyright 2015-2016 ForgeRock AS.
 * Portions copyright 2021 OSSTech Corporation
 */

package org.forgerock.openam.core.rest.devices;

import com.iplanet.sso.SSOException;
import com.sun.identity.authentication.service.AuthD;
import com.sun.identity.idm.AMIdentity;
import com.sun.identity.idm.AMIdentityRepository;
import com.sun.identity.idm.IdRepoException;
import com.sun.identity.idm.IdSearchControl;
import com.sun.identity.idm.IdSearchResults;
import com.sun.identity.idm.IdType;
import com.sun.identity.sm.SMSException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.forgerock.json.JsonException;
import org.forgerock.json.JsonValue;
import org.forgerock.json.resource.InternalServerErrorException;
import org.forgerock.openam.core.rest.devices.services.AuthenticatorDeviceServiceFactory;
import org.forgerock.openam.core.rest.devices.services.DeviceService;

/**
 * DAO for handling the retrieval and saving of a user's devices.
 *
 * @since 13.0.0
 */
public class UserDevicesDao {

    private static final int NO_LIMIT = 0;

    private final AuthenticatorDeviceServiceFactory serviceFactory;

    /**
     * Construct a new UserDevicesDao with the provided serviceFactory.
     *
     * @param serviceFactory The DeviceServiceFactory used to generate specific services for realms.
     */
    public UserDevicesDao(AuthenticatorDeviceServiceFactory serviceFactory) {
        this.serviceFactory = serviceFactory;
    }

    /**
     * Gets a user's device profiles. The returned profiles must be stored in JSON format.
     *
     * @param username User whose profiles to return.
     * @param realm Realm in which we are operating.
     * @return A list of device profiles.
     * @throws InternalServerErrorException If there is a problem retrieving the device profiles.
     */
    public List<JsonValue> getDeviceProfiles(String username, String realm)
            throws InternalServerErrorException {

        List<JsonValue> devices = new ArrayList<>();

        final AMIdentity identity = getIdentity(username, realm);
        try {
            final DeviceService deviceService = serviceFactory.create(realm);
            final String attrName = deviceService.getConfigStorageAttributeName();
            final DeviceSerialisation deviceSerialisation = deviceService.getDeviceSerialisationStrategy();

            Set<String> set = (Set<String>) identity.getAttribute(attrName);

            for (String profile : set) {
                try {
                    devices.add(deviceSerialisation.stringToDeviceProfile(profile));
                } catch (JsonException jve) {
                    //RTE, generally indicative that the profile attribute name has changed (still return devices set)
                }
            }

            return devices;

        } catch (SSOException | IdRepoException | SMSException e) {
            throw new InternalServerErrorException(e.getMessage(), e);
        }
    }

    /**
     * Saves a user's device profiles.
     *
     * @param username User whose profiles to return.
     * @param realm Realm in which we are operating.
     * @param profiles The user's device profiles to store.
     *
     * @throws InternalServerErrorException If there is a problem storing the device profiles.
     */
    public void saveDeviceProfiles(String username, String realm, List<JsonValue> profiles)
            throws InternalServerErrorException {

        final AMIdentity identity = getIdentity(username, realm);


        Set<String> vals = new HashSet<>();

        try {
            final DeviceService deviceService = serviceFactory.create(realm);
            final DeviceSerialisation deviceSerialisation = deviceService.getDeviceSerialisationStrategy();
            final String attrName = deviceService.getConfigStorageAttributeName();

            for (JsonValue profile : profiles) {
                vals.add(deviceSerialisation.deviceProfileToString(profile));
            }

            Map<String, Set> attrMap = new HashMap<>();
            attrMap.put(attrName, vals);

            identity.setAttributes(attrMap);
            identity.store();
        } catch (SSOException | IdRepoException | SMSException e) {
            throw new InternalServerErrorException(e.getMessage(), e);
        }
    }

    /**
     * Gets the {@code AMIdentity} for the authenticated user.
     *
     * @param userName The user's name.
     * @param realm The user's realm.
     * @return An {@code AMIdentity}.
     * @throws InternalServerErrorException If there is a problem getting the user's identity.
     */
    private AMIdentity getIdentity(String userName, String realm) throws InternalServerErrorException {
        final AMIdentity amIdentity;
        final AMIdentityRepository amIdRepo = AuthD.getAuth().getAMIdentityRepository(realm);

        final IdSearchControl idsc = new IdSearchControl();
        idsc.setAllReturnAttributes(true);

        Set<AMIdentity> results = Collections.emptySet();

        try {
            idsc.setMaxResults(NO_LIMIT);
            IdSearchResults searchResults = amIdRepo.searchIdentities(IdType.USER, userName, idsc, false, false);
            if (searchResults != null) {
                results = searchResults.getSearchResults();
            }

            if (results.isEmpty()) {
                throw new IdRepoException("getIdentity : User " + userName + " is not found");
            } else if (results.size() > 1) {
                throw new IdRepoException("getIdentity : More than one user found for the userName " + userName);
            }

            amIdentity = results.iterator().next();
        } catch (IdRepoException | SSOException e) {
            throw new InternalServerErrorException(e.getMessage(), e);
        }

        return amIdentity;
    }
}
