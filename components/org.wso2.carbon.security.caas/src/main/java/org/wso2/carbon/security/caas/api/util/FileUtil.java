/*
* Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
package org.wso2.carbon.security.caas.api.util;

import org.wso2.carbon.security.caas.api.exception.CarbonSecurityServerException;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.introspector.BeanAccess;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryIteratorException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/**
 * File util to write read yaml configurations
 */
public class FileUtil {
    private FileUtil() {
    }

    public static <T> T readConfigFile(String filePath, Class<T> classType) throws CarbonSecurityServerException {
        Path file = Paths.get(filePath, new String[0]);
        return readConfigFile(file, classType);
    }

    public static <T> T readConfigFile(Path file, Class<T> classType) throws CarbonSecurityServerException {

        try (InputStreamReader inputStreamReader =
                     new InputStreamReader(Files.newInputStream(file), StandardCharsets.UTF_8)) {
            Yaml yaml = new Yaml();
            yaml.setBeanAccess(BeanAccess.FIELD);
            return yaml.loadAs(inputStreamReader, classType);
        } catch (IOException e) {
            throw new CarbonSecurityServerException(
                    String.format("Error in reading file %s", file.toString()), e);
        }
    }

    public static <T> List<T> readConfigFiles(Path path, Class<T> classType, String fileNameRegex)
            throws CarbonSecurityServerException {

        ArrayList configEntries = new ArrayList();
        if (Files.exists(path, new LinkOption[0])) {
            try {
                DirectoryStream directoryStream = Files.newDirectoryStream(path, fileNameRegex);
                Throwable ex = null;

                try {
                    Iterator iterator = directoryStream.iterator();

                    while (iterator.hasNext()) {
                        Path file = (Path) iterator.next();
                        InputStreamReader in =
                                new InputStreamReader(
                                        Files.newInputStream(file, new OpenOption[0]), StandardCharsets.UTF_8);
                        Yaml yaml = new Yaml();
                        yaml.setBeanAccess(BeanAccess.FIELD);
                        configEntries.add(yaml.loadAs(in, classType));
                    }
                } catch (Throwable e) {
                    ex = e;
                    throw e;
                } finally {
                    if (directoryStream != null) {
                        if (ex != null) {
                            try {
                                directoryStream.close();
                            } catch (Throwable throwable) {
                                throw new CarbonSecurityServerException(
                                        String.format("Error in reading file %s", new Object[]{path.getFileName()}),
                                        throwable);
                            }
                        } else {
                            directoryStream.close();
                        }
                    }

                }
            } catch (IOException | DirectoryIteratorException e) {
                throw new CarbonSecurityServerException(
                        String.format("Failed to read identity connector files from path: %s",
                                      new Object[]{path.toString()}), e);
            }
        }

        return configEntries;
    }

    public static <T> void writeConfigFiles(Path file, Object data)
            throws CarbonSecurityServerException {

        if (Files.exists(file, new LinkOption[0])) {
            try {
                Yaml yaml = new Yaml();
                yaml.setBeanAccess(BeanAccess.FIELD);
                try (Writer writer = new OutputStreamWriter(new FileOutputStream(file.toFile()),
                                                            StandardCharsets.UTF_8)) {
                    yaml.dump(data, writer);
                }
            } catch (IOException e) {
                throw new CarbonSecurityServerException(
                        String.format("Error in reading file %s", new Object[] { file.toString() }), e);
            }
        } else {
            throw new CarbonSecurityServerException(
                    String.format("Configuration file %s is not available.", new Object[] { file.toString() }));
        }
    }
}
