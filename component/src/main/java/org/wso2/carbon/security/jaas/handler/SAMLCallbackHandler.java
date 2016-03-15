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

package org.wso2.carbon.security.jaas.handler;

import io.netty.handler.codec.http.HttpRequest;
import io.netty.handler.codec.http.QueryStringDecoder;
import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Response;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.io.UnmarshallingException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.wso2.carbon.security.jaas.CarbonCallback;
import org.wso2.carbon.security.jaas.HTTPCallbackHandler;
import org.wso2.carbon.security.jaas.util.CarbonSecurityConstants;
import org.xml.sax.SAXException;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.List;
import java.util.Map;

/**
 * <p>
 * This class builds SAML Assertion from the Authorization header
 * </p>
 */
public class SAMLCallbackHandler implements HTTPCallbackHandler {

    private static boolean openSAMLBootstrapped = false;

    private HttpRequest httpRequest;

    private Assertion samlAssertion;

    @Override
    public void setHTTPRequest(HttpRequest httpRequest) {
        this.httpRequest = httpRequest;
    }

    @Override
    public boolean canHandle() {

        if (httpRequest != null) {

            QueryStringDecoder queryStringDecoder = new QueryStringDecoder(httpRequest.getUri());
            Map<String, List<String>> requestParameters = queryStringDecoder.parameters();
            String b64SAMLResponse = requestParameters.get("SAMLResponse").get(0);

            ByteArrayInputStream SAMLResponseInputStream = null;

            try {
                String responseXml;
                responseXml = new String(org.opensaml.xml.util.Base64.decode(b64SAMLResponse), "UTF-8");
                if (!openSAMLBootstrapped) {
                    DefaultBootstrap.bootstrap();
                    openSAMLBootstrapped = true;
                }

                DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
                documentBuilderFactory.setNamespaceAware(true);
                DocumentBuilder docBuilder = documentBuilderFactory.newDocumentBuilder();
                docBuilder.setEntityResolver((publicId, systemId) -> {
                    throw new SAXException("AuthnRequest contains invalid elements. Possibly " +
                            "an XML External Entity (XXE) attack.");
                });
                SAMLResponseInputStream = new ByteArrayInputStream(responseXml.getBytes("UTF8"));
                Document document = docBuilder.parse(SAMLResponseInputStream);

                Element element = document.getDocumentElement();

                UnmarshallerFactory unmarshallerFactory = Configuration.getUnmarshallerFactory();
                Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(element);

                XMLObject xmlObject = unmarshaller.unmarshall(element);
                if(xmlObject instanceof Response) {
                    samlAssertion = ((Response) xmlObject).getAssertions().get(0);
                } else if (xmlObject instanceof Assertion) {
                    samlAssertion = (Assertion) xmlObject;
                } else {
                    return false;
                }

                return true;

            } catch (UnsupportedEncodingException e) {
                //throw new CarbonSecurityException("Error decoding SAML Response", e);
            } catch (ConfigurationException e) {
                //throw new CarbonSecurityException("Failed to bootstrap OpenSAML 2 Library", e);
            } catch (ParserConfigurationException | SAXException | IOException | UnmarshallingException e) {
                //throw new CarbonSecurityException("Failed to parse SAML XML Response", e);
            } finally {
                if (SAMLResponseInputStream != null) {
                    try {
                        SAMLResponseInputStream.close();
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }
            }

        }
        return false;
    }

    @Override
    public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {

        if(callbacks != null && callbacks.length > 0) {
            if (callbacks[0] instanceof CarbonCallback) {
                ((CarbonCallback) callbacks[0]).setContent(samlAssertion);
            }
        }
    }

}
