/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.apache.xml.security.utils.resolver.implementations;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;

import org.apache.xml.security.signature.XMLSignatureInput;
import org.apache.xml.security.signature.XMLSignatureFileInput;
import org.apache.xml.security.utils.resolver.ResourceResolverContext;
import org.apache.xml.security.utils.resolver.ResourceResolverException;
import org.apache.xml.security.utils.resolver.ResourceResolverSpi;

/**
 */
public class ResolverAnonymous extends ResourceResolverSpi {

    private final Path resourcePath;

    /**
     * @param filename
     * @throws IOException
     */
    public ResolverAnonymous(String filename) throws IOException {
        this(Path.of(filename));
    }

    /**
     * @param resourcePath
     */
    public ResolverAnonymous(Path resourcePath) {
        this.resourcePath = resourcePath;
    }

    /** {@inheritDoc} */
    @Override
    public XMLSignatureInput engineResolveURI(ResourceResolverContext context) throws ResourceResolverException {
        try {
            XMLSignatureInput input = new XMLSignatureFileInput(resourcePath);
            input.setSecureValidation(context.secureValidation);
            return input;
        } catch (IOException e) {
            throw new ResourceResolverException(e, context.uriToResolve, context.baseUri, "generic.EmptyMessage");
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean engineCanResolveURI(ResourceResolverContext context) {
        return context.uriToResolve == null;
    }

}
