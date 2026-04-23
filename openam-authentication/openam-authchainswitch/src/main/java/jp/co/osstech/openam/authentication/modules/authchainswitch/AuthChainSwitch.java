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
 * Portions Copyrighted 2026 OSSTech Corporation
 */


package jp.co.osstech.openam.authentication.modules.authchainswitch;

import static jp.co.osstech.openam.authentication.modules.authchainswitch.AuthChainSwitchConstants.*;
import static com.sun.identity.authentication.client.AuthClientUtils.parseRequestParameters;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.Map;
import java.util.MissingResourceException;
import java.util.ResourceBundle;
import java.util.Set;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.ChoiceCallback;
import javax.security.auth.login.LoginException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.forgerock.openam.utils.StringUtils;
import com.sun.identity.common.configuration.MapValueParser;

import com.sun.identity.authentication.AuthContext;
import com.sun.identity.authentication.server.AuthContextLocal;
import com.sun.identity.authentication.service.AuthException;
import com.sun.identity.authentication.service.AuthUtils;
import com.sun.identity.authentication.service.LoginState;
import com.sun.identity.authentication.spi.AMLoginModule;
import com.sun.identity.authentication.spi.AuthLoginException;
import com.sun.identity.authentication.spi.PagePropertiesCallback;
import com.sun.identity.authentication.util.ISAuthConstants;
import com.sun.identity.shared.locale.L10NMessageImpl;
import com.sun.identity.idm.AMIdentity;
import com.sun.identity.idm.IdRepoException;
import com.sun.identity.idm.IdUtils;
import com.sun.identity.shared.datastruct.CollectionHelper;
import com.sun.identity.shared.datastruct.ValueNotFoundException;
import com.sun.identity.shared.debug.Debug;
import com.sun.identity.shared.encode.CookieUtils;
import com.sun.identity.sm.DNMapper;
import com.iplanet.dpro.session.service.InternalSession;
import com.iplanet.sso.SSOException;
import com.iplanet.sso.SSOToken;
import com.iplanet.sso.SSOTokenManager;


/**
 * AuthChainSwitch authentication module.
 */
public class AuthChainSwitch extends AMLoginModule {

    private final static String DEBUG_NAME = "AuthChainSwitch";
    private final static Debug debug = Debug.getInstance(DEBUG_NAME);

    private final static String amAuthAuthChainSwitch = "amAuthAuthChainSwitch";
    private final static String SUCCESS_AUTH_CHAIN = "[Empty]";

    private String userName = null;
    private String serviceName = null;
    private String realm = null;
    private AuthContextLocal acLocal;
    private AMIdentity id;
    private Principal principal = null;
    private int previousLength = 0;
    private String attribute_name = null;
    private Map<String, String> authChainMap;
    private String defaultAuthChain = null;
    private int authLevel = DEFAULT_AUTH_LEVEL;
    private static final MapValueParser MAP_VALUE_PARSER = new MapValueParser();
    private ArrayList<String> choices = new ArrayList<String>();
    private boolean session_upgrade = false;
    private boolean session_upgrade_empty_allow = false;
    private boolean mapping_value_nomatch_error = true;
    private String cookie_name = null;
    private int cookie_max_age = 0;
    private AuthChainSwitchHttpServletRequest request;
    private HttpServletResponse response;

    private ResourceBundle bundle;
    public AuthChainSwitch() {
        super();
    }


    @Override
    public void init(Subject subject, Map sharedState, Map options) {

        debug.message("AuthChainSwitch::init");

        this.bundle = amCache.getResBundle(amAuthAuthChainSwitch, getLoginLocale());

        attribute_name = CollectionHelper.getMapAttr(options, AUTHCHAIN_ATTR_NAME);
        defaultAuthChain = CollectionHelper.getMapAttr(options, DEFAULT_AUTHCHAIN);
        try {
            Set<String> tmp = CollectionHelper.getMapSetThrows(options, ATTRVALUE_AUTHCHAIN_MAP);
            authChainMap = MAP_VALUE_PARSER.parse(tmp);
        } catch (ValueNotFoundException e) {
            debug.error("MAP_VALUE_PARSER.parse Error: ", e);
        }
        authLevel = CollectionHelper.getIntMapAttr(options, AUTHLEVEL, DEFAULT_AUTH_LEVEL, debug);
        session_upgrade_empty_allow = Boolean.parseBoolean(CollectionHelper.getMapAttr(options, SESSION_UPGRADE_EMPTY_ALLOW));
        cookie_max_age = CollectionHelper.getIntMapAttr(options, COOKIE_MAX_AGE, DEFAULT_MAX_AGE, debug);
        cookie_name = CollectionHelper.getMapAttr(options, COOKIE_NAME);
        mapping_value_nomatch_error = CollectionHelper.getBooleanMapAttr(options, MAPPING_VALUE_NOMATCH_ERROR, true);

        userName = (String) sharedState.get(getUserKey());
        try {
            checkForSessionAndGetUsernameAndUUID();
            realm = DNMapper.orgNameToRealmName(getRequestOrg());
            id = IdUtils.getIdentity(userName, realm);
        } catch (AuthLoginException e) {
            debug.message("amAuthChainSwitch :: init() : Unable to get userName ", e);
        } catch (SSOException e) {
            debug.message("amAuthChainSwitch :: init() : Unable to get userName ", e);
        }
    }

    @Override
    public int process(Callback[] callbacks, int state) throws LoginException {

        String attr_value = null;
        debug.message("AuthChainSwitch::process state: {}", state);
        if (StringUtils.isEmpty(userName)) {
            debug.error("amAuthChainSwitch ::process() : no UserName");
            throw new AuthLoginException("amAuth", "noUserName", null);
        }

        HttpServletRequest original_request = getHttpServletRequest();
        response = getHttpServletResponse();
        if (null == original_request || null == response) {
            return processError(bundle.getString("NullRequest"),
                    "AuthChainSwitch :: process() : Http Request or Response is null - "
                    + "programmatic login is not supported.");
        }
        request = new AuthChainSwitchHttpServletRequest(original_request);
        request.setUserName(userName);

        if (acLocal != null) {
            state = LOGIN_1STEP;
        }

        switch (state) {
            case START:
                Set<String> attr_values = null;
                if (StringUtils.isBlank(attribute_name)) {
                    return processError(bundle.getString(
                            "SettingError"),
                            "amAuthChainSwitch :: process() - " + AUTHCHAIN_ATTR_NAME + " is null.");
                }
                if (authChainMap.isEmpty()) {
                    return processError(bundle.getString(
                            "SettingError"),
                            "amAuthChainSwitch :: process() - " + ATTRVALUE_AUTHCHAIN_MAP + " is null.");
                }
                if (StringUtils.isBlank(defaultAuthChain)) {
                    return processError(bundle.getString(
                            "SettingError"),
                            "amAuthChainSwitch :: process() - " + DEFAULT_AUTHCHAIN + " is null.");
                }

                if (id == null) {
                    return processError(bundle.getString(
                            "localAuthChainError"),
                            "amAuthChainSwitch :: process() - getIdentity Error: "
                                    + "(AMIdentity)id is null");
                }
                try {
                    attr_values = id.getAttribute(attribute_name);
                } catch (SSOException e) {
                    return processError(bundle.getString(
                            "localAuthChainError"),
                            "amAuthChainSwitch :: process() - getAttribute Error: "
                                    + "Unable to get authchain attrvalue ", e);
                } catch (IdRepoException e) {
                    return processError(bundle.getString(
                            "localAuthChainError"),
                            "amAuthChainSwitch :: process() - getAttribute Error: "
                                    + "Unable to get authchain attrvalue ", e);
                }

                if (attr_values.isEmpty()) {
                    serviceName = defaultAuthChain;
                } else {
                    int authchain_list_size = attr_values.size();
                    debug.message("amAuthChainSwitch ::process() : getAttribute values."
                                     + " userName: [" + userName + "] attrvalues: [{}]", attr_values);
                    Iterator<String> it = attr_values.iterator();
                    String choice;
                    ArrayList<String> choice_descriptions = new ArrayList<String>();

                    for (int i = 0; i < authchain_list_size; i++) {
                        choice = it.next();
                        if (choice.isEmpty() || !authChainMap.containsKey(choice)) {
                            if (mapping_value_nomatch_error) {
                                return processError(bundle.getString(
                                    "localAuthChainError"),
                                    "amAuthChainSwitch :: process() - Invalid user attribute value: "
                                            + "userName:[{}] value:[{}] ", userName, choice);
                            }
                            continue;
                        }
                        if (session_upgrade && !session_upgrade_empty_allow
                                && authChainMap.get(choice).equals(SUCCESS_AUTH_CHAIN)){
                            continue;
                        }
                        try {
                            choice_descriptions.add(bundle.getString(choice));
                        } catch (MissingResourceException e) {
                           debug.message("amAuthChainSwitch ::process() : bundle.getString() MissingResourceException."
                                          + " key: [{}]", choice);
                           choice_descriptions.add(choice);
                        }
                        choices.add(choice);
                        attr_value = choice;
                    }
                    if (choice_descriptions.size() == 0) {
                        attr_value = null;
                        serviceName = defaultAuthChain;
                    } else if (choice_descriptions.size() > 1) {
                        int selectedIndex = 0;
                        String cookie_choice = get_choice_cookie(request);
                        if (cookie_choice != null && choices.contains(cookie_choice)) {
                            selectedIndex = choices.indexOf(cookie_choice);
                        }
                        ChoiceCallback callback = new ChoiceCallback(bundle.getString("choiceprompt"),
                                (String[]) choice_descriptions.toArray(new String[choice_descriptions.size()]), 0, false);
                        callback.setSelectedIndex(selectedIndex);
                        replaceCallback(LOGIN_SELECT , 0, callback);
                        debug.message("amAuthChainSwitch ::process() : ChoiceCallback."
                                 + " choice_descriptions: [{}] selectedIndex:[{}]",
                                 choice_descriptions, selectedIndex);
                        return LOGIN_SELECT;
                    }
                    debug.message("amAuthChainSwitch ::process() : getAttribute Success."
                            + " userName: [" + userName + "] attrvalue: [" + attr_value + "]");
                }
                return authchain_login_exec(attr_value);

            case LOGIN_SELECT:
                if (callbacks[0] instanceof ChoiceCallback) {
                    int[] selectedIndexes = ((ChoiceCallback)callbacks[0]).getSelectedIndexes();

                    if (selectedIndexes.length == 1 && selectedIndexes[0] >= 0 &&
                            selectedIndexes[0] < choices.size()) {
                        attr_value = choices.get(selectedIndexes[0]);
                    } else {
                        return processError(bundle.getString("authFailed"),
                                "AuthChainSwitch :: process() : Callback Error.(index Error: [{}])", selectedIndexes);
                    }
                    serviceName = null;
                    addCookieToResponse(request, response, attr_value);
                    debug.message("amAuthChainSwitch :: process() : ChoiceCallback."
                              + " user choice value: [{}]", attr_value);
                    return authchain_login_exec(attr_value);
                }
                return processError(bundle.getString("authFailed"),
                          "AuthChainSwitch :: process() : Callback Error.(no ChoiceCallback)");

            case LOGIN_1STEP:
            case LOGIN_2STEP:
            case LOGIN_3STEP:
            case LOGIN_4STEP:
            case LOGIN_5STEP:
            case LOGIN_6STEP:
            case LOGIN_7STEP:
            case LOGIN_8STEP:
            case LOGIN_9STEP:
            case LOGIN_10STEP:
                return stepLogin(callbacks);

            default:
                return processError(bundle.getString("invalidLoginState"),
                        "Unrecognised login state: {}", state);
        }
    }

    @Override
    public Principal getPrincipal() {
        return principal;
    }

    private String get_choice_cookie(HttpServletRequest req) {
        String retVal = null;
        if (req != null && (!StringUtils.isEmpty(cookie_name))) {
            Cookie cookie = CookieUtils.getCookieFromReq(req, cookie_name);
            if (cookie != null) {
                retVal = CookieUtils.getCookieValue(cookie);
            }
        }
        return retVal;
    }

    private void addCookieToResponse(HttpServletRequest req, HttpServletResponse res, String value){
        int expire = (60 * 60 * 24) * cookie_max_age;
        if (expire == 0) {
            debug.message("amAuthChainSwitch :: addCookieToResponse() : Not SetCookie Header. expire is 0");
            return;
        }
        final Set<String> cookieDomains = AuthUtils.getCookieDomainsForRequest(req);
        debug.message("amAuthChainSwitch :: addCookieToResponse() : SetCookie value: [{}]"
                + " expire:[{}]", value, expire);
        if (cookieDomains.isEmpty()) {
            CookieUtils.addCookieToResponse(req, res, CookieUtils.newCookie(cookie_name, value, expire, "/", null));
        } else {
            for (String domain : cookieDomains) {
                CookieUtils.addCookieToResponse(req, res, CookieUtils.newCookie(cookie_name, value, expire, "/", domain));
            }
        }
    }


    private int authchain_login_exec(String attr_value) throws AuthLoginException {

        if (!StringUtils.isEmpty(attr_value)) {
            serviceName = authChainMap.get(attr_value);
        }

        if (StringUtils.isBlank(serviceName)) {
            return processError(bundle.getString("localAuthChainError"),
                    "amAuthChainSwitch :: process() - Invalid value: "
                            + "userName:[{}] value:[{}] ", userName, attr_value);
        }

        if (serviceName.equals(SUCCESS_AUTH_CHAIN)) {
            if (!session_upgrade || session_upgrade_empty_allow ){
                debug.message("amAuthChainSwitch ::process() : Success without calling authChain."
                            + " userName: [" + userName + "]");
                return success(userName);
            } else {
                return processError(bundle.getString("sessionUpgradeError"),
                        "amAuthChainSwitch :: process() - sessionUpgradeError: Can't authenticate with [Empty]"
                            + " during session upgrade. userName:[{}]", userName);
            }
        }


        // The locale of the client
        String loc = getLoginLocale().getLanguage();
        // The DN representation of the client realm
        String orgDN = DNMapper.orgNameToDN(realm);
        LoginState intLoginState;

        try {
            Hashtable dataHash = parseRequestParameters(request);
            intLoginState = new LoginState();
            intLoginState.setLocale(loc);
            acLocal = intLoginState.createAuthContext(request, response, null, dataHash);
            acLocal.setLoginState(intLoginState);
            acLocal.setOrgDN(orgDN);
            debug.message("amAuthChainSwitch ::process() : authenticationContext.login(). servieName: ["
                           + serviceName + "] userName: [" + userName + "]");
            acLocal.login(AuthContext.IndexType.SERVICE, serviceName, loc);
        } catch (AuthException e) {
            return processError(bundle.getString("authFailed"),
                      "AuthChainSwitch :: process() : failed to login authenticationContext ", e);
        }
        return injectCallbacks(null);
    }


    private void checkForSessionAndGetUsernameAndUUID() throws SSOException, AuthLoginException {
        if (StringUtils.isEmpty(userName)) {
            // session upgrade case. Need to find the user ID from the old
            SSOTokenManager mgr = SSOTokenManager.getInstance();
            InternalSession isess = getLoginState(amAuthAuthChainSwitch).getOldSession();
            if (isess == null) {
                throw new AuthLoginException("amAuth", "noInternalSession", null);
            }
            SSOToken token = mgr.createSSOToken(isess.getID().toString());
            token.getPrincipal().getName();
            userName = token.getProperty("UserToken");
            if (debug.messageEnabled()) {
                debug.message("amAuthChainSwitch.process() : Username from SSOToken : " + userName);
            }
            if (StringUtils.isEmpty(userName)) {
                throw new AuthLoginException("amAuth", "noUserName", null);
            }
            session_upgrade = true;
        }
    }



    /**
     * In conjuncture with injectCallbacks, steps through an internal auth chain
     * (stored in authenticationContext) until it's completed by repeatedly
     * injecting the callbacks from the internal chain's modules and submitting
     * them until the status has confirmed failed or succeeded.
     */
    private int stepLogin(final Callback[] realCallbacks) throws AuthLoginException {

        if (acLocal == null ||
                acLocal.getStatus().equals(AuthContext.Status.FAILED)) {

            String failureMessage = null;
            String lockoutMessage = null;
            StringBuilder sbMessage = new StringBuilder();

            if (acLocal != null) {
                failureMessage = acLocal.getErrorMessage();
                lockoutMessage = acLocal.getLockoutMsg();
            }
            if (failureMessage != null && failureMessage.length() > 0) {
                sbMessage.append(failureMessage);
                if (lockoutMessage != null && lockoutMessage.length() > 0) {
                    sbMessage.append(" ");
                    sbMessage.append(lockoutMessage);
                }
            } else if (lockoutMessage != null && lockoutMessage.length() > 0) {
                sbMessage.append(lockoutMessage);
            } else {
                sbMessage.append(bundle.getString("localAuthFailed"));
            }

            // error response of local authentication to log
            return processError(new String(sbMessage),
                    "AuthChainSwitch :: stepLogin() : failed to perform local authentication - {} ",
                    new String(sbMessage));
        } else if (acLocal.getStatus().equals(AuthContext.Status.IN_PROGRESS)) {
            return injectCallbacks(realCallbacks);
        } else if (acLocal.getStatus().equals(AuthContext.Status.SUCCESS)) {
            String local_userName = null;
            try {
                local_userName = acLocal.getSSOToken().getProperty("UserToken");
            } catch (SSOException e) {
                return processError(bundle.getString("localAuthFailed"),
                        "AuthChainSwitch :: stepLogin() : failed to perform local authentication",e);
            } catch (L10NMessageImpl l10NMessage) {
                return processError(l10NMessage, null,
                       "AuthChainSwitch :: stepLogin() : failed to perform local authentication - {} ",
                        l10NMessage.getL10NMessage(getLoginLocale()));
            } finally {
                acLocal.logout();
            }
            if (!userName.equals(local_userName)) {
                return processError(bundle.getString("localAuthFailed"),
                        "AuthChainSwitch :: stepLogin() : local authentication UserName does not match: [{}]", local_userName);
            }
            return success(userName);
        }
        return processError(bundle.getString("invalidLoginState"), "AuthChainSwitch :: stepLogin() : unexpected login state");
    }

    private int success(String userName) {
        debug.message("amAuthChainSwitch.success() : userName : " + userName + " AuthLevel:" + authLevel);
        storeUsernamePasswd(userName, null);
        try {
            setAuthLevel(authLevel);
            setUserSessionProperty(AUTH_SESSION_PROPERTY_NAME, serviceName);
        } catch (Exception e) {
            debug.error("Unable to set authLevel :[{}]",authLevel, e);
        }
        principal = new AuthChainSwitchPrincipal(userName);
        return ISAuthConstants.LOGIN_SUCCEED;
    }

    /**
     * Submits completed callbacks (from the just-completed step - the first
     * time this is called realCallbacks should
     * be null as there is no just-completed step in the internal auth module),
     * and injects the next lot if there are any.
     */
    private int injectCallbacks(final Callback[] realCallbacks) throws AuthLoginException {

        /**
         * Every time injectCallback() is called, we need to set the current
         * request object  to the authentication context.
        */
        acLocal.getLoginState().setHttpServletRequest(request);
        acLocal.getLoginState().setHttpServletResponse(response);

        if (acLocal.hasMoreRequirements()) {
            //replace existing callbacks
            if (realCallbacks != null) {
                acLocal.submitRequirements(realCallbacks);
            }

            if (acLocal.hasMoreRequirements()) {
                return injectAndReturn();
            } else { //completed auth, status should be failure or success, allow stepLogin to return
                return finishLoginModule();
            }
        }

        return processError(bundle.getString("invalidLoginState"),
                "AuthChainSwitch :: injectCallbacks() : Authentication Module - invalid login state");
    }

    /**
     * Draws the next set of callbacks on to the current (externally-facing) auth module's step.
     */
    private int injectAndReturn() throws AuthLoginException {
        Callback[] injectedCallbacks = acLocal.getRequirements();

        while (injectedCallbacks.length == 0) {
            acLocal.submitRequirements(injectedCallbacks);
            if (acLocal.hasMoreRequirements()) {
                injectedCallbacks = acLocal.getRequirements();
            } else { //completed auth with zero callbacks status should be failure or success, allow stepLogin to return
                return finishLoginModule();
            }
        }

        if (injectedCallbacks.length > MAX_CALLBACKS_INJECTED) {
            return processError(bundle.getString("localAuthFailed"),
                    "AuthChainSwitch  :: injectAndReturn() :"
                            + "Local authentication failed");
        }

        int LOGIN_STEP = injectedCallbacks.length + 1;

        PagePropertiesCallback pc = (PagePropertiesCallback) acLocal.getLoginState().getReceivedInfo()[0];
        replaceHeader(LOGIN_STEP, pc.getHeader());
        String childChainStage = pc.getModuleName() + pc.getPageState();
        debug.message("AuthChainSwitch::injectAndReturn childChainStage: {}", childChainStage);
        request.setAttribute(ISAuthConstants.INTERNAL_AUTH_STAGE_REQUEST_ATTR, childChainStage);

        if (previousLength > 0) { //reset
            int cLength = Math.min(previousLength, getCallback(LOGIN_STEP).length);
            for (int i = 0; i < cLength; i++) {
                replaceCallback(LOGIN_STEP, i, DEFAULT_CALLBACK);
            }
        }

        for (int i = 0; i < injectedCallbacks.length; i++) {
            replaceCallback(LOGIN_STEP, i, injectedCallbacks[i]);
        }

        previousLength = injectedCallbacks.length;
        return LOGIN_STEP;
    }

    /**
     * Finishes a login module and then progresses to the next state.
     */
    private int finishLoginModule() throws AuthLoginException {
        if (acLocal.getStatus().equals(AuthContext.Status.IN_PROGRESS)) {
            return processError(bundle.getString("invalidLoginState"),
                    "AuthChainSwitch :: injectCallbacks() : Authentication Module - invalid login state");
        }
        return stepLogin(null);
    }

    /**
     * Writes out an error debug (if a throwable and debug message are provided)
     * and returns a user-facing error page.
     */
    private int processError(String headerMessage, String debugMessage,
                             Object... messageParameters) throws AuthLoginException {
        if (null != debugMessage) {
            debug.error(debugMessage, messageParameters);
        }
        substituteHeader(STATE_ERROR, headerMessage);
        return STATE_ERROR;
    }

    /**
     * Writes out an error debug (if a throwable and debug message are provided)
     * and returns a user-facing error page.
     */
    private int processError(L10NMessageImpl e, String headerMessageCode,
                             String debugMessage, Object... messageParameters)
            throws AuthLoginException {

        if (null == e) {
            return processError(headerMessageCode, debugMessage, messageParameters);
        }
        String headerMessage;
        if (null == headerMessageCode) {
            headerMessage = e.getL10NMessage(getLoginLocale());
        } else {
            headerMessage = bundle.getString(headerMessageCode);
        }
        if (debugMessage != null) {
            debug.error(debugMessage, messageParameters, e);
        }
        substituteHeader(STATE_ERROR, headerMessage);
        return STATE_ERROR;
    }
}
