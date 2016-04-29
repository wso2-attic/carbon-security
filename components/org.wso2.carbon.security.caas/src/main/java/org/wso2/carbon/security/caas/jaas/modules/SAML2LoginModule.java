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

package org.wso2.carbon.security.caas.jaas.modules;

//import org.opensaml.saml2.core.Assertion;
//import org.opensaml.security.SAMLSignatureProfileValidator;
//import org.opensaml.xml.security.credential.Credential;
//import org.opensaml.xml.security.x509.BasicX509Credential;
//import org.opensaml.xml.signature.SignatureValidator;
//import org.opensaml.xml.validation.ValidationException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.security.caas.jaas.CarbonPrincipal;

import java.security.KeyStore;
import java.util.HashMap;
import java.util.Map;
import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;

//import CarbonCallback;
//import org.wso2.carbon.security.jaas.exception.CarbonSecurityException;
//import CarbonSecurityConstants;
//import javax.security.auth.callback.Callback;
//import javax.security.auth.callback.UnsupportedCallbackException;
//import java.io.FileInputStream;
//import java.io.IOException;
//import java.security.KeyStoreException;
//import java.security.NoSuchAlgorithmException;
//import java.security.cert.CertificateException;
//import java.security.cert.X509Certificate;


/**
 * JAAS LoginModule that verifies a SAML response from an IdP.
 */
public class SAML2LoginModule implements LoginModule {

    private static final Logger log = LoggerFactory.getLogger(SAML2LoginModule.class);
    //string constants used as parameters in the options passed to the loginModule
    public static final String OPT_KEYSTORE_FILE = "keystorefile";
    public static final String OPT_KEYSTORE_INSTANCE = "keystore";
    public static final String OPT_IDP_CERT_ALIAS = "certalias";
    public static final String OPT_KEYSTORE_PW = "keystorepassword";

    private static Map<String, KeyStore> keystoreCache = new HashMap<>();

    //details of the keystore, populated with default entries.
    private String keyStoreFile = "wso2carbon.jks";
    private String certificateAlias = "wso2carbon";
    private String keyStorePassword = "wso2carbon";
    private String b64SAMLResponse;
//    private Assertion samlAssertion;
    private CarbonPrincipal userPrincipal;
    private KeyStore keyStore;
    boolean success;
    private Subject subject;
    private CallbackHandler callbackHandler;

    private Map<String, ?> options;


    /**
     * @param subject         The <code>Subject</code> instance that needs to be authenticated
     * @param callbackHandler Expects a <code>CarbonCallBackHandler</code> instance
     * @param sharedState     This module does not use any parameters from shared state
     * @param options         If all three are provided, uses the options "keystorefile", "keystorealias",
     *                        "keystorepassword" to override the
     *                        default keystore.
     */
    @Override
    public void initialize(Subject subject, CallbackHandler callbackHandler, Map<String, ?> sharedState,
                           Map<String, ?> options) {
        this.subject = subject;
        this.callbackHandler = callbackHandler;
        this.options = options;
        //shared state is ignored as it is note used.

        if (options != null && options.containsKey(OPT_KEYSTORE_FILE) && options.containsKey(OPT_IDP_CERT_ALIAS)
                && options.containsKey(OPT_KEYSTORE_PW)) {
            keyStoreFile = (String) options.get(OPT_KEYSTORE_FILE);
            certificateAlias = (String) options.get(OPT_IDP_CERT_ALIAS);
            keyStorePassword = (String) options.get(OPT_KEYSTORE_PW);
        }
        if (options != null && options.containsKey(OPT_KEYSTORE_INSTANCE)) {
            this.keyStore = (KeyStore) options.get(OPT_KEYSTORE_INSTANCE);
        }
        this.success = false;

    }

    @Override
    public boolean login() throws LoginException {

//        CarbonCallback<Assertion> samlCallback = new CarbonCallback<>(CarbonSecurityConstants.SAML_LOGIN_MODULE);
//        Callback[] callbacks = {samlCallback};
//
//        try {
//            callbackHandler.handle(callbacks);
//        } catch (IOException | UnsupportedCallbackException e) {
//            throw new LoginException("Failed fetch SAML data");
//        }
//
//        samlAssertion = samlCallback.getContent();
//
//        try {
//            validateSignature(samlAssertion);
//        } catch (ValidationException e) {
//            throw new LoginException("Failed to validate SAML Signature");
//        }
//        if (samlAssertion != null) { //assertions exist and are not encrypted
//            org.opensaml.saml2.core.Subject samlSubject = samlAssertion.getSubject();
//            if (samlSubject != null && samlSubject.getNameID().getValue() != null) {
//                success = true;
//                return true;
//            }
//        }

        return true;
    }

    @Override
    public boolean commit() throws LoginException {
//        userPrincipal = new CarbonPrincipal(samlAssertion.getSubject().getNameID().getValue());
//        subject.getPrincipals().add(userPrincipal);
        return true;
    }

    @Override
    public boolean abort() throws LoginException {
        success = false;
        subject.getPrincipals().remove(userPrincipal);
        return true;
    }

    @Override
    public boolean logout() throws LoginException {
        success = false;
        subject.getPrincipals().remove(userPrincipal);
        return true;
    }

//    private void validateSignature(Assertion samlAssertion) throws ValidationException {
//        if (samlAssertion == null) {
//            throw new ValidationException("Validation Failed");
//        }
//
//        SAMLSignatureProfileValidator profileValidator = new SAMLSignatureProfileValidator();
//        try {
//            //validate the saml profile of the response
//            profileValidator.validate(samlAssertion.getSignature());
//            Credential verificationCredential = getVerificationCredential();
//            SignatureValidator sigValidator = new SignatureValidator(verificationCredential);
//            //validate the signature of the response
//            sigValidator.validate(samlAssertion.getSignature());
//        } catch (Exception e) {
//            throw new ValidationException("Validation Failed", e);
//        }
//    }


    /**
     * <p>
     * This method retrieves the certificate from the keystore
     * </p>
     *
     * @return
     * @throws Exception
     */
//    private Credential getVerificationCredential() throws CarbonSecurityException {
//        BasicX509Credential basicX509Credential = new BasicX509Credential();
//        if (keyStore == null) {
//            keyStore = getKeystore(keyStoreFile, keyStorePassword.toCharArray());
//        }
//
//        try {
//            basicX509Credential.setEntityCertificate((X509Certificate) keyStore.getCertificate(certificateAlias));
//            basicX509Credential.setPublicKey(keyStore.getCertificate(certificateAlias).getPublicKey());
//        } catch (KeyStoreException e) {
//            throw new CarbonSecurityException("Failed to fetch certificate '" + certificateAlias + "' from keystore '"
//                    + keyStoreFile + "'", e);
//        }
//
//        return basicX509Credential;
//
//    }

//    private static KeyStore getKeystore(String keyStorePath, char[] keyStorePassword) throws CarbonSecurityException {
//        KeyStore keyStore;
//
//        if (keystoreCache.containsKey(keyStorePath))
//            return keystoreCache.get(keyStorePath);
//
//        try {
//            keyStore = KeyStore.getInstance("jks");
//            FileInputStream fileInputStream = new FileInputStream(keyStorePath);
//            keyStore.load(fileInputStream, keyStorePassword);
//
//            fileInputStream.close();
//
//            keystoreCache.put(keyStorePath, keyStore);
//        } catch (KeyStoreException | CertificateException | NoSuchAlgorithmException | IOException e) {
//            throw new CarbonSecurityException("Failed to load keystore '" + keyStorePath + "'", e);
//        }
//        return keyStore;
//    }
}
