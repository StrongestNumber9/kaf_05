/*
 * Teragrep Authentication Module for Apache Kafka (kaf_05)
 * Copyright (C) 2019-2026 Suomen Kanuuna Oy
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 *
 * Additional permission under GNU Affero General Public License version 3
 * section 7
 *
 * If you modify this Program, or any covered work, by linking or combining it
 * with other code, such other code is not for that reason alone subject to any
 * of the requirements of the GNU Affero GPL version 3 as long as this Program
 * is the same Program as licensed from Suomen Kanuuna Oy without any additional
 * modifications.
 *
 * Supplemented terms under GNU Affero General Public License version 3
 * section 7
 *
 * Origin of the software must be attributed to Suomen Kanuuna Oy. Any modified
 * versions must be marked as "Modified version of" The Program.
 *
 * Names of the licensors and authors may not be used for publicity purposes.
 *
 * No rights are granted for use of trade names, trademarks, or service marks
 * which are in The Program if any.
 *
 * Licensee must indemnify licensors and authors for any liability that these
 * contractual assumptions impose on licensors and authors.
 *
 * To the extent this program is licensed as part of the Commercial versions of
 * Teragrep, the applicable Commercial License may apply to this file if you as
 * a licensee so wish it.
 */
package com.teragrep.kaf_05;

import com.google.gson.Gson;
import org.apache.kafka.common.KafkaException;
import org.apache.kafka.common.security.auth.AuthenticateCallbackHandler;
import org.apache.kafka.common.security.plain.PlainAuthenticateCallback;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.AppConfigurationEntry;
import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.util.List;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public final class TeragrepAuthenticateCallbackHandler implements AuthenticateCallbackHandler {

    // logging
    private static final Logger logger = LoggerFactory.getLogger(TeragrepAuthenticateCallbackHandler.class);

    private ReloadingAuthenticator clientAuthenticator = null;
    private Authenticator writerAuthenticator = null;
    private Authenticator brokerAuthenticator = null;
    private String identitySuffix;

    // for testing only
    void configure(
            String clientCredentialPath,
            String writerCredentialPath,
            String brokerCredentialPath,
            String identitySuffixPath
    ) {
        this.clientAuthenticator = new ReloadingAuthenticator(clientCredentialPath);
        this.writerAuthenticator = new Authenticator(writerCredentialPath);
        this.brokerAuthenticator = new Authenticator(brokerCredentialPath);
        this.identitySuffix = getIdentitySuffix(identitySuffixPath);
    }

    @Override
    public void configure(Map<String, ?> configs, String mechanism, List<AppConfigurationEntry> jaasConfigEntries) {

        // Should be just one set of options, I hope
        if (jaasConfigEntries.size() > 1) {
            logger.warn("Found more than one JAAS configuration entry for <{}>", mechanism);
        }
        Map<String, ?> jaasOptions = jaasConfigEntries.get(0).getOptions();
        final String credentialsPath = getPath(
                jaasOptions, "credentials.file", "/opt/teragrep/kaf_05/etc/credentials.json"
        );
        final String writerPath = getPath(
                jaasOptions, "writer.file", "/opt/teragrep/kaf_05/etc/credentials.writer.json"
        );
        final String brokerPath = getPath(
                jaasOptions, "cluster.file", "/opt/teragrep/kaf_05/etc/credentials.cluster.json"
        );
        final String identitySuffixPath = getPath(
                jaasOptions, "identitySuffix.file", "/opt/teragrep/kaf_05/etc/identitySuffix.json"
        );

        this.clientAuthenticator = new ReloadingAuthenticator(credentialsPath);
        this.writerAuthenticator = new Authenticator(writerPath);
        this.brokerAuthenticator = new Authenticator(brokerPath);
        this.identitySuffix = getIdentitySuffix(identitySuffixPath);
        logger.info("TeragrepAuthenticateCallbackHandler initialized");
    }

    private String getPath(Map<String, ?> configs, String property, String fallback) {
        final Object config = configs.get(property);
        final String path;
        if (config instanceof String && config != "") {
            path = (String) config;
            logger.info("Resolved property <[{}]> to <[{}]>", property, path);
        }
        else {
            path = fallback;
            logger.info("Didn't find property <[{}]>, defaulting to <[{}]>", property, fallback);
        }
        return path;
    }

    @Override
    public void handle(Callback[] callbacks) throws UnsupportedCallbackException {
        String username = null;
        for (Callback callback : callbacks) {
            if (callback instanceof NameCallback)
                username = ((NameCallback) callback).getDefaultName();
            else if (callback instanceof PlainAuthenticateCallback) {
                PlainAuthenticateCallback plainCallback = (PlainAuthenticateCallback) callback;

                boolean authenticated = authenticate(username, plainCallback.password());

                // return status to callback requester
                plainCallback.authenticated(authenticated);
            }
            else
                throw new UnsupportedCallbackException(callback);
        }
    }

    @Override
    public void close() throws KafkaException {
    }

    boolean authenticate(String username, char[] password) {
        if (brokerAuthenticator.authenticate(username, password)) {
            logger.info("BrokerAuthentication successful for user <[{}]>", username);
            return true;
        }
        else if (writerAuthenticator.authenticate(username, password)) {
            logger.info("WriterAuthentication successful for user <[{}]>", username);
            return true;
        }
        else if (clientAuthenticator.authenticate(username + identitySuffix, password)) {
            logger.info("ClientAuthentication successful for user <[{}]>", username);
            return true;
        }
        else {
            logger.info("Authentication failed for user <[{}]>", username);
            return false;
        }
    }

    private String getIdentitySuffix(String identitySuffixPath) {
        final Gson gson = new Gson();

        String identitySuffixString = "";
        try {
            final BufferedReader identitySuffixReader = new BufferedReader(new FileReader(identitySuffixPath));
            IdentitySuffix identitySuffixObj = gson.fromJson(identitySuffixReader, IdentitySuffix.class);
            identitySuffixString = identitySuffixObj.identitySuffix;
        }
        catch (FileNotFoundException ignored) {

        }
        return identitySuffixString;
    }

}
