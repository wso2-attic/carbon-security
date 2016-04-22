/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wso2.carbon.security.jaas.modules;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.ReadOnlyJWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.kernel.context.PrivilegedCarbonContext;
import org.wso2.carbon.security.internal.CarbonSecurityDataHolder;
import org.wso2.carbon.security.jaas.CarbonCallback;
import org.wso2.carbon.security.jaas.CarbonPrincipal;
import org.wso2.carbon.security.jaas.util.CarbonSecurityConstants;
import org.wso2.carbon.security.user.core.bean.User;
import org.wso2.carbon.security.user.core.exception.IdentityStoreException;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Date;
import java.util.Map;
import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;


/**
 * <p>
 * This LoginModule authenticates users with JWT tokens.
 * Upon successful authentication, <code>CarbonPrincipal</code> with user information is added to the subject.
 * This LoginModule does not recognize any options defined in the login configuration.
 * </p>
 *
 * @since 1.0.0
 */
public class JWTLoginModule implements LoginModule {

    private static final Logger log = LoggerFactory.getLogger(JWTLoginModule.class);
    private static final String DEFAULT_TRUSTSTORE_PASSWORD = "wso2carbon";
    private static final String DEFAULT_CERTIFICATE_ALIAS = "wso2carbon";

    //String constants used as parameters in the options passed to the loginModule.
    private static final String OPT_TRUSTSTORE_PATH = "truststorepath";
    public static final String OPT_TRUSTSTORE_PW = "truststorepassword";
    public static final String OPT_IDP_CERT_ALIAS = "alias";

    private Subject subject;
    private CallbackHandler callbackHandler;
    private Map<String, ?> sharedState;
    private Map<String, ?> options;
    private boolean succeeded;
    private boolean commitSucceeded;
    private SignedJWT signedJWT;
    private CarbonPrincipal carbonPrincipal;
    private String trustStorePath;
    private String trustStorePassword;
    private String certificateAlias;

    @Override
    public void initialize(Subject subject, CallbackHandler callbackHandler, Map<String, ?> sharedState,
                           Map<String, ?> options) {

        this.subject = subject;
        this.callbackHandler = callbackHandler;
        this.sharedState = sharedState;
        this.options = options;

        if (options != null && options.containsKey(OPT_TRUSTSTORE_PATH) && options.containsKey(OPT_TRUSTSTORE_PW)
            && options.containsKey(OPT_IDP_CERT_ALIAS)) {
            trustStorePath = (String) options.get(OPT_TRUSTSTORE_PATH);
            if (!Paths.get(trustStorePath).isAbsolute()) {
                trustStorePath = getAbsolutePath(trustStorePath).toString();
            }
            trustStorePassword = (String) options.get(OPT_TRUSTSTORE_PW);
            certificateAlias = (String) options.get(OPT_IDP_CERT_ALIAS);
        } else {
            trustStorePath = getDefaultTrustStorePath().toString();
            trustStorePassword = DEFAULT_TRUSTSTORE_PASSWORD;
            certificateAlias = DEFAULT_CERTIFICATE_ALIAS;
        }
    }

    @Override
    public boolean login() throws LoginException {

        CarbonCallback<SignedJWT> jwtCarbonCallback = new CarbonCallback<>(CarbonSecurityConstants.JWT_LOGIN_MODULE);
        Callback[] callbacks = {jwtCarbonCallback};

        try {
            callbackHandler.handle(callbacks);
        } catch (IOException | UnsupportedCallbackException e) {
            log.error("Error while handling callbacks.", e);
            throw new LoginException("Error while handling callbacks.");
        }

        signedJWT = jwtCarbonCallback.getContent();
        if (verifySignature(signedJWT)) {
            succeeded = true;
        } else {
            succeeded = false;
        }
        //TODO Add Audit logs
        return succeeded;
    }

    @Override
    public boolean commit() throws LoginException {
        if (!succeeded) {
            commitSucceeded = false;
        } else {

            try {
                ReadOnlyJWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
                User user;
                try {
                    user = CarbonSecurityDataHolder.getInstance().getCarbonRealmService().getIdentityStore()
                            .getUser(claimsSet.getSubject());
                } catch (IdentityStoreException e) {
                    throw new LoginException("User with name '" + claimsSet.getSubject() + "' is not available");
                }

                carbonPrincipal = new CarbonPrincipal(user);

                if (!subject.getPrincipals().contains(carbonPrincipal)) {
                    subject.getPrincipals().add(carbonPrincipal);
                }

                PrivilegedCarbonContext privilegedCarbonContext =
                        (PrivilegedCarbonContext) PrivilegedCarbonContext.getCurrentContext();
                privilegedCarbonContext.setUserPrincipal(carbonPrincipal);

                commitSucceeded = true;
            } catch (ParseException e) {
                log.error("Error while retrieving claims from JWT Token", e);
                commitSucceeded = false;
            }
        }

        return commitSucceeded;
    }

    @Override
    public boolean abort() throws LoginException {
        if (!succeeded) {
            return false;
        } else if (!commitSucceeded) {
            // login success but overall authentication failed
            succeeded = false;
            signedJWT = null;
            carbonPrincipal = null;
        } else {
            // overall authentication success and commit success,
            // but someone else's commit failed
            logout();
        }
        return true;
    }

    @Override
    public boolean logout() throws LoginException {
        subject.getPrincipals().remove(carbonPrincipal);
        succeeded = false;
        commitSucceeded = false;
        signedJWT = null;
        carbonPrincipal = null;
        return true;
    }

    /**
     * <p>Verifies the signature of a signed JWT.
     *
     * @param signedJWT Signed JWT which needed to be verified.
     * @return true if the signature of the given JWT can is verified else false.
     */
    private boolean verifySignature(SignedJWT signedJWT) {
        try {

            if (signedJWT != null) {
                if (new Date().before(signedJWT.getJWTClaimsSet().getExpirationTime())) {
                    JWSVerifier verifier =
                            new RSASSAVerifier((RSAPublicKey) getPublicKey(trustStorePath, trustStorePassword,
                                                                           certificateAlias));
                    return signedJWT.verify(verifier);
                } else {
                    log.warn("Token has expired.");
                }
            }
        } catch (ParseException | IOException | KeyStoreException | CertificateException |
                NoSuchAlgorithmException | UnrecoverableKeyException | JOSEException e) {
            log.error("Error occurred while JWT signature verification", e);
        }
        return false;
    }

    /**
     * Returns public key from a certificate when provided key store path, key store password and certificate alias.
     *
     * @param keyStorePath     Absolute path to the key store.
     * @param keyStorePassword Password of the key store.
     * @param alias            Alias of the public key certificate that needed be extracted.
     * @return PublicKey extracted public key.
     * @throws IOException
     * @throws KeyStoreException
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     * @throws UnrecoverableKeyException
     */

    private PublicKey getPublicKey(String keyStorePath, String keyStorePassword, String alias)
            throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException,
                   UnrecoverableKeyException {

        try (InputStream inputStream = new FileInputStream(keyStorePath)) {

            KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
            keystore.load(inputStream, keyStorePassword.toCharArray());
            Certificate cert = keystore.getCertificate(alias);

            return cert.getPublicKey();
        }
    }


    /**
     * Retrieves the file path of the client trust store.
     *
     * @return String representing the trust store path.
     */
    private Path getDefaultTrustStorePath() {
        //TODO Get the key store from a util.
        return Paths.get(System.getProperty("carbon.home"), "conf", "data-bridge", "client-truststore.jks");
    }

    /**
     * Returns the absolute path for a given relative path to $CARBON_HOME.
     *
     * @param relativePath path of the file relative to $CARBON_HOME.
     * @return absolute path.
     */
    private Path getAbsolutePath(String relativePath) {
        return Paths.get(System.getProperty("carbon.home")).resolve(Paths.get(relativePath)).normalize();
    }
}
