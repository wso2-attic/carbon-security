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

package org.wso2.carbon.security.osgi;

import io.netty.handler.codec.http.DefaultHttpRequest;
import io.netty.handler.codec.http.HttpMethod;
import io.netty.handler.codec.http.HttpRequest;
import io.netty.handler.codec.http.HttpVersion;
import org.ops4j.pax.exam.Configuration;
import org.ops4j.pax.exam.Option;
import org.ops4j.pax.exam.spi.reactors.ExamReactorStrategy;
import org.ops4j.pax.exam.spi.reactors.PerClass;
import org.ops4j.pax.exam.testng.listener.PaxExam;
import org.osgi.framework.BundleContext;
import org.testng.Assert;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;
import org.wso2.carbon.kernel.context.PrivilegedCarbonContext;
import org.wso2.carbon.kernel.utils.CarbonServerInfo;
import org.wso2.carbon.security.jaas.CarbonCallbackHandler;
import org.wso2.carbon.security.osgi.util.SecurityOSGiTestUtils;

import java.nio.file.Paths;
import java.util.Base64;
import java.util.List;
import javax.inject.Inject;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

import static org.ops4j.pax.exam.CoreOptions.mavenBundle;
import static org.ops4j.pax.exam.CoreOptions.systemProperty;

/**
 * JAAS OSGI Tests.
 */

@Listeners(PaxExam.class)
@ExamReactorStrategy(PerClass.class)
public class JAASTests {

    @Inject
    private BundleContext bundleContext;

    @Inject
    private CarbonServerInfo carbonServerInfo;

    @Configuration
    public Option[] createConfiguration() {

        List<Option> optionList = SecurityOSGiTestUtils.getDefaultSecurityPAXOptions();

        optionList.add(mavenBundle()
                               .groupId("org.wso2.carbon")
                               .artifactId("org.wso2.carbon.core")
                               .versionAsInProject());
        optionList.add(mavenBundle()
                               .groupId("net.minidev.wso2")
                               .artifactId("json-smart")
                               .versionAsInProject());
        optionList.add(mavenBundle()
                               .groupId("org.wso2.orbit.com.nimbusds")
                               .artifactId("nimbus-jose-jwt")
                               .versionAsInProject());
        optionList.add(mavenBundle()
                               .groupId("net.minidev")
                               .artifactId("asm")
                               .versionAsInProject());
        optionList.add(systemProperty("java.security.auth.login.config").value(Paths.get(
                SecurityOSGiTestUtils.getCarbonHome(), "conf", "security", "carbon-jaas.config").toString()));

        return optionList.toArray(new Option[optionList.size()]);
    }

    @Test
    public void testBasicLogin() throws LoginException {

        PrivilegedCarbonContext.destroyCurrentContext();
        HttpRequest httpRequest = getHTTPRequestWithAuthzHeader("Basic " + Base64.getEncoder().encodeToString
                ("admin:admin".getBytes()));

        CarbonCallbackHandler callbackHandler = new CarbonCallbackHandler(httpRequest);

        LoginContext loginContext = new LoginContext("CarbonSecurityBasicConfig", callbackHandler);

        loginContext.login();
        Assert.assertTrue(true);
    }

    @Test
    public void testJWTLogin() throws LoginException {

        PrivilegedCarbonContext.destroyCurrentContext();
        String encodedJWT = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhZG1pbiIsImV4cCI6NDEwMjQyNTAwMH0.E2SstYw2upLmIf0FqYNM_hS" +
                            "PJ9j-vrYwep9nEAHu-OgxEBGU9-e1UXT9FTQ9ZJnkLgO4DypF_kAW2xbA6SOhwSpT_BQHcXJta_yCrPcnxH09vtk" +
                            "HN35zl9UzS7d3CCLaKrDNWMWnf6Z9XcbDJjOvakVhbf7UFPI0ec0fNx0RbbQ";

        HttpRequest httpRequest = getHTTPRequestWithAuthzHeader("Bearer " + encodedJWT);

        CarbonCallbackHandler callbackHandler = new CarbonCallbackHandler(httpRequest);
        LoginContext loginContext = new LoginContext("CarbonSecurityJWTConfig", callbackHandler);

        loginContext.login();
        Assert.assertTrue(true);
    }

    private static HttpRequest getHTTPRequestWithAuthzHeader(String headerContent) {

        HttpRequest httpRequest = new DefaultHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.GET, "");
        httpRequest.headers().add("Authorization", headerContent);

        return httpRequest;
    }

}
