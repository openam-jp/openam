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
 * Copyright 2026 OSSTech Corporation
 */
package jp.co.osstech.openam.core.rest.identities;

import java.util.Set;

import org.forgerock.openam.rest.RestUtils;

import com.iplanet.sso.SSOException;
import com.sun.identity.idm.AMIdentity;
import com.sun.identity.idm.AMIdentityRepository;
import com.sun.identity.idm.IdConstants;
import com.sun.identity.idm.IdRepoException;
import com.sun.identity.idm.IdSearchResults;
import com.sun.identity.idm.IdType;
import com.sun.identity.idm.IdUtils;
import com.sun.identity.shared.debug.Debug;
import com.sun.identity.sm.DNMapper;
import com.sun.identity.sm.SMSEntry;

/**
 * Utilities for identifying users.
 */
public class UserUtils {

    private static Debug logger = Debug.getInstance("frRest");

    private static final String ID_DSAME_USER = "id=dsameuser,ou=user," + SMSEntry.getRootSuffix();
    private static final String ID_AMADMIN_USER = "id=" + IdConstants.AMADMIN_USER + ",ou=user," +
            SMSEntry.getRootSuffix();
    private static final String ID_ANONYMOUS_USER = "id=" + IdConstants.ANONYMOUS_USER + ",ou=user," +
            SMSEntry.getRootSuffix();
    private static final String ID_URLACCESS_AGENT = "id=amService-URLAccessAgent,ou=user," +
            SMSEntry.getRootSuffix();

    /**
     * Returns true if identity is dsameuser.
     *
     * @param amid user object
     * @return true if identity is dsameuser
     */
    public static boolean isDsameUser(AMIdentity amid) {
        return isSameUser(ID_DSAME_USER, amid);
    }

    /**
     * Returns true if identity is amadmin user.
     *
     * @param amid user object
     * @return true if identity is amadmin user
     */
    public static boolean isAmAdminUser(AMIdentity amid) {
        return isSameUser(ID_AMADMIN_USER, amid);
    }

    /**
     * Returns true if identity is anonymous user.
     *
     * @param amid user object
     * @return true if identity is anonymous user
     */
    public static boolean isAnonymousUser(AMIdentity amid) {
        if (isSameUser(ID_ANONYMOUS_USER, amid)) {
            try {
                // Check if anonymous user was deleted on SpecialRepo
                String orgDN = DNMapper.orgNameToDN(amid.getRealm());
                AMIdentityRepository amIdRepo = IdUtils.getAMIdentityRepository(orgDN);
                IdSearchResults results = amIdRepo.getSpecialIdentities(
                        RestUtils.getToken(), IdType.USER, orgDN);
                Set<AMIdentity> specialUsers = results.getSearchResults();
                return specialUsers != null && specialUsers.contains(amid);
            } catch (IdRepoException | SSOException e) {
                logger.error("UserUtils.isAnonymousUser() :: Unable to get special users");
            }
        }
        return false;
    }

    /**
     * Returns true if identity is amService-URLAccessAgent.
     *
     * @param amid user object
     * @return true if identity is amService-URLAccessAgent
     */
    public static boolean isURLAccessAgent(AMIdentity amid) {
        return isSameUser(ID_URLACCESS_AGENT, amid);
    }

    private static boolean isSameUser(String univid, AMIdentity target) {
        if (target.getType().equals(IdType.USER)) {
            return univid.equalsIgnoreCase(target.getUniversalId());
        }
        return false;
    }
}
