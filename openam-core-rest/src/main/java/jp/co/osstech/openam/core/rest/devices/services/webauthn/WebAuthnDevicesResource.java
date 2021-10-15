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
 * Copyright 2019-2021 OSSTech Corporation
 */
package jp.co.osstech.openam.core.rest.devices.services.webauthn;

import com.iplanet.sso.SSOException;
import com.sun.identity.authentication.service.AuthD;
import com.sun.identity.idm.AMIdentity;
import com.sun.identity.idm.AMIdentityRepository;
import com.sun.identity.idm.IdRepoException;
import com.sun.identity.idm.IdSearchControl;
import com.sun.identity.idm.IdSearchResults;
import com.sun.identity.idm.IdType;
import com.sun.identity.shared.debug.Debug;
import com.sun.identity.sm.SMSException;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import javax.inject.Inject;
import javax.inject.Named;
import org.forgerock.json.resource.ActionRequest;
import org.forgerock.json.resource.ActionResponse;
import org.forgerock.json.resource.CreateRequest;
import org.forgerock.json.resource.DeleteRequest;
import org.forgerock.json.resource.NotSupportedException;
import org.forgerock.json.resource.PatchRequest;
import org.forgerock.json.resource.QueryRequest;
import org.forgerock.json.resource.QueryResourceHandler;
import org.forgerock.json.resource.QueryResponse;
import org.forgerock.json.resource.ReadRequest;
import org.forgerock.json.resource.ResourceException;
import org.forgerock.json.resource.ResourceResponse;
import static org.forgerock.json.resource.Responses.newQueryResponse;
import org.forgerock.json.resource.UpdateRequest;
import org.forgerock.services.context.Context;
import org.forgerock.util.promise.Promise;
import javax.security.auth.Subject;
import org.forgerock.openam.core.rest.devices.services.AuthenticatorDeviceServiceFactory;
import static jp.co.osstech.openam.core.rest.devices.services.webauthn.AuthenticatorWebAuthnServiceFactory.FACTORY_NAME;
import org.forgerock.json.JsonValue;
import org.forgerock.json.resource.InternalServerErrorException;
import org.forgerock.json.resource.NotFoundException;
import static org.forgerock.json.resource.Responses.newResourceResponse;
import org.forgerock.openam.rest.resource.ContextHelper;
import org.forgerock.openam.rest.RealmAwareResource;
import static org.forgerock.util.promise.Promises.newResultPromise;

public class WebAuthnDevicesResource extends RealmAwareResource {

    private final AuthenticatorDeviceServiceFactory<AuthenticatorWebAuthnService> webauthnServiceFactory;
    private final Debug debug;
    private static final int NO_LIMIT = 0;
    private static final String ENTRYUUID = "entryUUID";
    private final ContextHelper contextHelper;

    /**
     * Constructor that sets up the data accessing object, context helpers and the factory from which to produce
     * services appropriate to each realm.
     *
     * @param webauthnServiceFactory The factory used to generate appropriate services.
     * @param debug For debug purposes.
     */
    @Inject
    public WebAuthnDevicesResource(
            ContextHelper helper,
            @Named(FACTORY_NAME) AuthenticatorDeviceServiceFactory<AuthenticatorWebAuthnService> webauthnServiceFactory,
            @Named("frRest") Debug debug) {
        this.webauthnServiceFactory = webauthnServiceFactory;
        this.debug = debug;
        this.contextHelper = helper;
    }

    @Override
    public Promise<ActionResponse, ResourceException> actionCollection(Context cntxt, ActionRequest ar) {
        return new NotSupportedException("Not supported.").asPromise();
    }

    @Override
    public Promise<ActionResponse, ResourceException> actionInstance(Context cntxt, String string, ActionRequest ar) {
        return new NotSupportedException("Not supported.").asPromise();
    }

    @Override
    public Promise<ResourceResponse, ResourceException> createInstance(Context cntxt, CreateRequest cr) {
        return new NotSupportedException("Not supported.").asPromise();
    }

    @Override
    public Promise<ResourceResponse, ResourceException> deleteInstance(Context cntxt, String resourceId, DeleteRequest dr) {
        final Subject subject = getContextSubject(cntxt);
        String userName = contextHelper.getUserId(cntxt);
        String realm = getRealm(cntxt);
        JsonValue result = new JsonValue(new LinkedHashMap<String, Object>(1));
        try {
            AMIdentity userIdentity = getIdentity(userName, realm);
            Set<String> attrSet = (Set<String>) userIdentity.getAttribute(ENTRYUUID);
            String entryUUID = attrSet.iterator().next();

            AuthenticatorWebAuthnService realmWebAuthnService = webauthnServiceFactory.create(realm);
            Set<WebAuthnAuthenticator> authenticators = realmWebAuthnService.getAuthenticators(entryUUID.getBytes());

            boolean found = false;
            boolean delResult;
            for (WebAuthnAuthenticator authenticator : authenticators) {
                if (authenticator.getCredentialID().equals(resourceId)) {
                    found = true;
                    break;
                }
            }
            if (found) {
                delResult = realmWebAuthnService.deleteAuthenticator(resourceId);
            } else {
                return new NotFoundException("WebAuthnDevicesResource :: Delete -User device, " + resourceId + ", not found.").asPromise();
            }
            result.put("success", delResult);
            return newResultPromise(newResourceResponse(resourceId, "0", result));
        }
        catch (SMSException ex) {
            debug.error("WebAuthnDevicesResource :: Delete - Unable to communicate with the SMS.", ex);
            return new InternalServerErrorException().asPromise();
        }
        catch (SSOException|InternalServerErrorException ex) {
            debug.error("WebAuthnDevicesResource :: Delete - Unable to retrieve realm or user data from request context", ex);
            return new InternalServerErrorException().asPromise();
        }
        catch (IdRepoException ex) {
            debug.error("WebAuthnDevicesResource :: Delete - Unable to retrieve identity attribute", ex);
            return new InternalServerErrorException().asPromise();
        }
    }

    @Override
    public Promise<ResourceResponse, ResourceException> patchInstance(Context cntxt, String string, PatchRequest pr) {
        return new NotSupportedException("Not supported.").asPromise();
    }

    @Override
    public Promise<QueryResponse, ResourceException> queryCollection(Context cntxt, QueryRequest qr, QueryResourceHandler qrh) {
        final Subject subject = getContextSubject(cntxt);
        String userName = contextHelper.getUserId(cntxt);
        String realm = getRealm(cntxt);

        try {
            AuthenticatorWebAuthnService realmWebAuthnService = webauthnServiceFactory.create(realm);
            AMIdentity userIdentity = getIdentity(userName, realm);

            Set<String> attrSet = (Set<String>) userIdentity.getAttribute(ENTRYUUID);
            String entryUUID = attrSet.iterator().next();

            Set<WebAuthnAuthenticator> authenticators = realmWebAuthnService.getAuthenticators(entryUUID.getBytes());

            for (WebAuthnAuthenticator authenticator : authenticators) {

                String CredentialID = authenticator.getCredentialID();
                String CredentialName = authenticator.getCredentialName();
                Date CreatedDate = authenticator.getCreateTimestamp();

                Map<String, Object> map = new HashMap<>();
                map.put("uuid", CredentialID);
                map.put("deviceName", CredentialName);
                map.put("type", "fido2");
                map.put("createdDate", CreatedDate.getTime());

                qrh.handleResource(newResourceResponse(CredentialID, "0",
                        new JsonValue(map)));
            }

        }
        catch (SMSException ex) {
            debug.error("WebAuthnDevicesResource :: Query - Unable to communicate with the SMS.", ex);
            return new InternalServerErrorException().asPromise();
        }
        catch (SSOException|InternalServerErrorException ex) {
            debug.error("WebAuthnDevicesResource :: Query - Unable to retrieve identity data from request context", ex);
            return new InternalServerErrorException().asPromise();
        }
        catch (IdRepoException ex) {
            debug.error("WebAuthnDevicesResource :: Query - Unable to retrieve identity attribute", ex);
            return new InternalServerErrorException().asPromise();
        }
        return newResultPromise(newQueryResponse());
    }

    @Override
    public Promise<ResourceResponse, ResourceException> readInstance(Context cntxt, String string, ReadRequest rr) {
        return new NotSupportedException("Not supported.").asPromise();
    }

    @Override
    public Promise<ResourceResponse, ResourceException> updateInstance(Context cntxt, String string, UpdateRequest ur) {
        return new NotSupportedException("Not supported.").asPromise();
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
