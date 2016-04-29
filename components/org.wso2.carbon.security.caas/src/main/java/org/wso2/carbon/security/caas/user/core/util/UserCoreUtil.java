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

package org.wso2.carbon.security.caas.user.core.util;

import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.UUID;
import javax.xml.bind.DatatypeConverter;

/**
 * User core utils.
 */
public class UserCoreUtil {

    /**
     * Hash the given password using given algorithm.
     * @param password Password to be hashed.
     * @param salt Salt to be used to hash the password.
     * @param hashAlgo Hashing algorithm to be used.
     * @return Hash as a <code>String</code>
     * @throws NoSuchAlgorithmException
     */
    public static String hashPassword(char[] password, String salt, String hashAlgo) throws NoSuchAlgorithmException {

        // Merge the password and salt to a single array.
        char[] saltedPassword = Arrays.copyOf(password, password.length + salt.length());
        System.arraycopy(salt.toCharArray(), 0, saltedPassword, password.length, salt.length());

        MessageDigest messageDigest = MessageDigest.getInstance(hashAlgo);
        byte [] hash = messageDigest.digest(StandardCharsets.UTF_8.encode(CharBuffer.wrap(saltedPassword)).array());

        // Hash is in hex binary. Convert and return.
        return DatatypeConverter.printHexBinary(hash);
    }

    /**
     * Get a random id.
     * @return Random <code>UUID</code>
     */
    public static String getRandomId() {

        return UUID.randomUUID().toString();
    }
}
