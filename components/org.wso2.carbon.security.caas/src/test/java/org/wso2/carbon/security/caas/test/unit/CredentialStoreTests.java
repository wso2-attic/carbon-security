///*
// * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
// *
// * Licensed under the Apache License, Version 2.0 (the "License");
// * you may not use this file except in compliance with the License.
// * You may obtain a copy of the License at
// *
// * http://www.apache.org/licenses/LICENSE-2.0
// *
// * Unless required by applicable law or agreed to in writing, software
// * distributed under the License is distributed on an "AS IS" BASIS,
// * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// * See the License for the specific language governing permissions and
// * limitations under the License.
// */
//
//        Callback[] callbacks = new Callback[2];
//        PasswordCallback passwordCallback = new PasswordCallback("password", false);
//        NameCallback nameCallback = new NameCallback("username");
//
//        nameCallback.setName("admin");
//        passwordCallback.setPassword(new char[] {'a', 'd', 'm', 'i', 'n'});
//
//        callbacks[0] = passwordCallback;
//        callbacks[1] = nameCallback;
//
//        User user = Mockito.mock(User.class);
//        Mockito.when(user.getUserId()).thenReturn("admin");
//        // Mockito.when(user.getIdentityStoreId()).thenReturn("CSC1");
//
//        Mockito.doReturn(user).when(identityStore).getUser(callbacks);
//
//        AuthenticationContext authenticationContext = credentialStore.authenticate(callbacks);


        // Assert.assertNotNull(authenticationContext);
    }

    @Test
    public void testAuthenticateInvalidUser() throws CredentialStoreException, AuthenticationFailure,
            IdentityStoreException, UserNotFoundException {

        Mockito.doThrow(UserNotFoundException.class).when(identityStore).getUser(Mockito.any(Callback[].class));

        try {
            credentialStore.authenticate(new Callback[2]);
        } catch (AuthenticationFailure authenticationFailure) {
            return;
        }

        Assert.fail("Expecting an authentication failure.");
    }
}
