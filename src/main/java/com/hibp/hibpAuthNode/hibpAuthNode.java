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
 * Copyright 2017-2023 ForgeRock AS.
 */


package com.hibp.hibpAuthNode;

import static org.forgerock.json.JsonValue.field;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.PASSWORD;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.USERNAME;

import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.inject.Inject;

import org.forgerock.json.JsonValue;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.AbstractDecisionNode;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.InputState;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.NodeState;
import org.forgerock.openam.auth.node.api.OutputState;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.core.realms.Realm;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.inject.assistedinject.Assisted;
import com.iplanet.sso.SSOException;
import com.sun.identity.idm.AMIdentity;
import com.sun.identity.idm.IdRepoException;
import com.sun.identity.idm.IdType;
import com.sun.identity.idm.IdUtils;
import java.security.MessageDigest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import org.apache.commons.codec.binary.Hex;
/**
 * A node that checks to see if zero-page login headers have specified username and whether that username is in a group
 * permitted to use zero-page login headers.
 */
@Node.Metadata(outcomeProvider  = AbstractDecisionNode.OutcomeProvider.class,
               configClass      = hibpAuthNode.Config.class)
public class hibpAuthNode extends AbstractDecisionNode {

    private final Pattern DN_PATTERN = Pattern.compile("^[a-zA-Z0-9]=([^,]+),");
    private final Logger logger = LoggerFactory.getLogger(hibpAuthNode.class);
    private final Config config;
    private final Realm realm;
    private String loggerPrefix = "[HIBP]";

    /**
     * Configuration for the node.
     */
    public interface Config {

        @Attribute(order = 400)
        default int threshold() { return 0; }

        @Attribute(order = 500)
        default String breaches() { return "breaches"; }    
        
    }


    /**
     * Create the node using Guice injection. Just-in-time bindings can be used to obtain instances of other classes
     * from the plugin.
     *
     * @param config The service config.
     * @param realm The realm the node is in.
     */
    @Inject
    public hibpAuthNode(@Assisted Config config, @Assisted Realm realm) {
        this.config = config;
        this.realm = realm;
    }

    @Override
    public Action process(TreeContext context) {
        NodeState nodeState = context.getStateFor(this);
        String pass = nodeState.get("password").asString();
        logger.error(loggerPrefix + pass);
        if (pass == null) {

            return goTo(true).build();
        }
        String hex = null;
        try {
            MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
            sha1.update(pass.getBytes("UTF-8"));
            hex = Hex.encodeHexString(sha1.digest());
        } catch (Exception e) {
            // Assume compromised state
            return goTo(true).build();
        }
        logger.error(loggerPrefix + hex);
        int breaches = haveIBeenPwnedPassword(hex);
        JsonValue newSharedState = context.sharedState.copy();
        if (config.breaches() != null) newSharedState.put(config.breaches(), breaches);
        return goTo(false).build();
    }

    private int haveIBeenPwnedPassword(String hex) {
        hex = hex.toUpperCase();
        String prefix = hex.substring(0,5);
        int response = 0;
        try {
            URL url = new URL("https://api.pwnedpasswords.com/range/" + prefix);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setRequestProperty("Accept", "application/json");
            
            if (conn.getResponseCode() != 200) {
            }

            BufferedReader br = new BufferedReader(new InputStreamReader((conn.getInputStream())));
            String output;
            while ((output = br.readLine()) != null) {
                if (prefix.concat(output).startsWith(hex)) {
                    logger.error(loggerPrefix + "found matching password" +output);
                    // Compromised password match
                    String[] parts;
                    parts = output.split(":");
                    int breaches = Integer.parseInt(parts[1]);
                    // If password matched and number of hits is greater than threshold then compromised is true
                    if (breaches > config.threshold()) response = breaches;

                }
            }
            conn.disconnect();
        } catch (MalformedURLException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        // No matching password found
        logger.error(loggerPrefix + response);
        return response;
    }

}
