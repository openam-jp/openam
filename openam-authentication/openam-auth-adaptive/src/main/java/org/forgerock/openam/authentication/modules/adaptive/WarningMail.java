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

package org.forgerock.openam.authentication.modules.adaptive;

import java.lang.reflect.InvocationTargetException;
import java.security.AccessController;
import java.text.MessageFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Map;
import java.util.ResourceBundle;
import java.util.Set;

import javax.mail.MessagingException;

import org.forgerock.openam.services.email.MailServer;
import org.forgerock.openam.services.email.MailServerImpl;

import com.iplanet.sso.SSOException;
import com.sun.identity.security.AdminTokenAction;
import com.sun.identity.shared.debug.Debug;
import com.sun.identity.sm.SMSException;
import com.sun.identity.sm.ServiceConfig;
import com.sun.identity.sm.ServiceConfigManager;

/**
 * Class for sending warning mail.
 */
public class WarningMail {

    public static String PARAMETER_FROM_ADDRESS = "FROM_ADDRESS";
    public static String PARAMETER_TO_ADDRESS = "TO_ADDRESS";
    public static String PARAMETER_CONTENT_USER_ID = "USER_ID";
    public static String PARAMETER_CONTENT_DATE = "DATE";
    public static String PARAMETER_CONTENT_IP_ADDRESS = "IP_ADDRESS";
    public static String PARAMETER_CONTENT_COUNTRY_CODE = "COUNTRY_CODE";

    private static String PLACEHOLDER_USER_ID = "%UserIDInformation%";
    private static String PLACEHOLDER_DATE = "%DateInformation%";
    private static String PLACEHOLDER_IP_ADDRESS = "%IPAddressInformation%";
    private static String PLACEHOLDER_COUNTRY = "%CountryInformation%";

    private static String PROPERTY_KEY_SUBJECT = "wariningMailSubject";
    private static String PROPERTY_KEY_CONTENT = "wariningMailContent";
    private static String PROPERTY_KEY_INFORMATION_LINE = "InformationLineFormat";
    private static String PROPERTY_TITLE_KEY_USER_ID = "UserIDInformationTitle";
    private static String PROPERTY_TITLE_KEY_DATE = "DateInformationTitle";
    private static String PROPERTY_TITLE_KEY_IP_ADDRESS = "IPAddressInformationTitle";
    private static String PROPERTY_TITLE_KEY_COUNTRY = "CountryInformationTitle";

    private static String[][] MAIL_CONTENT_REPLACE_INFO = {
            {PLACEHOLDER_USER_ID, PROPERTY_TITLE_KEY_USER_ID, PARAMETER_CONTENT_USER_ID},
            {PLACEHOLDER_DATE, PROPERTY_TITLE_KEY_DATE, PARAMETER_CONTENT_DATE},
            {PLACEHOLDER_IP_ADDRESS, PROPERTY_TITLE_KEY_IP_ADDRESS, PARAMETER_CONTENT_IP_ADDRESS},
            {PLACEHOLDER_COUNTRY, PROPERTY_TITLE_KEY_COUNTRY, PARAMETER_CONTENT_COUNTRY_CODE}
    };

    private ResourceBundle bundle = null;
    private Map<String, String> params = null;
    private String realm = null;
    private Debug debug = null;

    /**
     * Constructor.
     * @param bundle ResourceBundle to be used for getting localized messages.
     * @param params A map that contains mail parameters.
     * @param realm Users realm.
     * @param debug Debug instance.
     */
    public WarningMail(ResourceBundle bundle, Map<String, String> params, String realm, Debug debug) {
        this.bundle = bundle;
        this.params = params;
        this.realm = realm;
        this.debug = debug;
    }

    /**
     * Send warning mail.
     */
    public void send() {

        MailServer mailServer = getMailServer(realm);
        if (mailServer == null) {
            return;
        }

        String fromAddress =  params.get(PARAMETER_FROM_ADDRESS);
        String toAddress =  params.get(PARAMETER_TO_ADDRESS);

        String subject = bundle.getString(PROPERTY_KEY_SUBJECT);
        String content = getContent();

        try {
            mailServer.sendEmail(fromAddress, toAddress, subject, content, null);
        } catch (MessagingException e) {
            debug.error("WarningMail.send : Unable to send warning mail", e);
        }
    }

    private String getContent() {

        Date now = new Date();
        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssXXX");
        String strDate = dateFormat.format(now);
        params.put(PARAMETER_CONTENT_DATE, strDate);

        String template = bundle.getString(PROPERTY_KEY_CONTENT);
        String lineFormat = bundle.getString(PROPERTY_KEY_INFORMATION_LINE);
        MessageFormat mf = new MessageFormat(lineFormat);
        String content = template;
        for (String[] info : MAIL_CONTENT_REPLACE_INFO) {
            String value = params.get(info[2]);
            String line;
            if (value != null) {
                String title = bundle.getString(info[1]);
                String[] args = {title, value};
                line = mf.format(args);
            } else {
                line = "";
            }
            content = content.replaceAll(info[0], line);
        }

        return content;
    }

    private MailServer getMailServer(String realm) {
        try {
            ServiceConfigManager mailmgr = new ServiceConfigManager(
                    AccessController.doPrivileged(AdminTokenAction.getInstance()),
                    MailServerImpl.SERVICE_NAME, MailServerImpl.SERVICE_VERSION);
            ServiceConfig mailscm = mailmgr.getOrganizationConfig(realm, null);

            if (!mailscm.exists()) {
                debug.error("WarningMail.getMailServer : Email Service not found in '{}' realm", realm);
                return null;
            }

            Map<String, Set<String>> mailattrs = mailscm.getAttributes();
            String mailServerClass = mailattrs.get("forgerockMailServerImplClassName").iterator().next();
            return Class.forName(mailServerClass).asSubclass(MailServer.class).getDeclaredConstructor(String.class)
                    .newInstance(realm);
        } catch (IllegalAccessException | SSOException | InstantiationException | ClassNotFoundException
                | InvocationTargetException | NoSuchMethodException | SMSException e) {
            debug.error("WarningMail.getMailServer : Unable to get mail server instance", e);
        }
        return null;
    }
}
