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
import org.wso2.carbon.security.jaas.CarbonCallbackHandler;
import org.wso2.carbon.security.osgi.util.SecurityOSGITestUtils;

import java.nio.file.Paths;
import java.util.Base64;
import java.util.List;
import javax.inject.Inject;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

import static org.ops4j.pax.exam.CoreOptions.systemProperty;

/**
 * JAAS OSGI Tests
 */

@Listeners(PaxExam.class)
@ExamReactorStrategy(PerClass.class)
public class JAASTests {

    @Inject
    private BundleContext bundleContext;

    @Configuration
    public Option[] createConfiguration() {

        List<Option> optionList = SecurityOSGITestUtils.getDefaultSecurityPAXOptions();
        optionList.add(systemProperty("java.security.auth.login.config").value(Paths.get(
                SecurityOSGITestUtils.getCarbonHome(), "conf", "security", "carbon-jaas.config").toString()));
        return optionList.toArray(new Option[optionList.size()]);
    }

    @Test
    public void testBasicLogin() throws LoginException {

        HttpRequest httpRequest = getHTTPRequestWithAuthzHeader("Basic " + Base64.getEncoder().encodeToString
                ("admin:admin".getBytes()));

        CarbonCallbackHandler callbackHandler = new CarbonCallbackHandler(httpRequest);

        LoginContext loginContext = new LoginContext("CarbonSecurityBasicConfig", callbackHandler);

        loginContext.login();
        Assert.assertTrue(true);
    }

    @Test
    public void testJWTLogin() throws LoginException {

        String encodedJWT = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0IiwiZXhwIjoxNDU5ODc2NzQ3fQ" +
                            ".D5CxKrcdSFRM5QFKj-FZNxiwnjSUovebjIt5OQTcHh5wfIT5svR6cvu_yIEZRFcMBjTu_Ddk" +
                            "-wwlXzZIzE2gHHI3rmkr8pXEBJGRpOz7Tll1f3w-oF32B40bLG2zBMmcZJnLq79Y13Xn3YO3Lfq0b3Y" +
                            "-o6oHZL8tKkuG7OkvTf8";
        HttpRequest httpRequest = getHTTPRequestWithAuthzHeader("Bearer " + encodedJWT);

        CarbonCallbackHandler callbackHandler = new CarbonCallbackHandler(httpRequest);
        LoginContext loginContext = new LoginContext("CarbonSecurityJWTConfig", callbackHandler);

        loginContext.login();
        Assert.assertTrue(true);
    }

    @Test
    public void testSAMLLogin() {
        //TODO
    }


    private static HttpRequest getHTTPRequestWithAuthzHeader(String headerContent) {

        HttpRequest httpRequest = new DefaultHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.GET, "");
        httpRequest.headers().add("Authorization", headerContent);

        return httpRequest;
    }

}
