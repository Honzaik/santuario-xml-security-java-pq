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
package org.apache.xml.security.algorithms.implementations;

import org.apache.xml.security.algorithms.JCEMapper;
import org.apache.xml.security.algorithms.SignatureAlgorithmSpi;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.signature.XMLSignatureException;

import java.lang.System.Logger;
import java.lang.System.Logger.Level;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

public abstract class SignatureBaseSLHDSA extends SignatureAlgorithmSpi {
    private static final Logger LOG = System.getLogger(SignatureBaseSLHDSA.class.getName());

    /** Field algorithm */
    private final Signature signatureAlgorithm;

    /**
     * Constructor SignatureSLHDSA
     *
     * @throws XMLSignatureException
     */
    public SignatureBaseSLHDSA() throws XMLSignatureException {
        this(null);
    }

    public SignatureBaseSLHDSA(Provider provider) throws XMLSignatureException {
        String algorithmID = JCEMapper.translateURItoJCEID(this.engineGetURI());
        LOG.log(Level.DEBUG, "Created SignatureSLHDSA using {}", algorithmID);

        try {
            if (provider == null) {
                String providerId = JCEMapper.getProviderId();
                if (providerId == null) {
                    this.signatureAlgorithm = Signature.getInstance(algorithmID);

                } else {
                    this.signatureAlgorithm = Signature.getInstance(algorithmID, providerId);
                }

            } else {
                this.signatureAlgorithm = Signature.getInstance(algorithmID, provider);
            }

        } catch (NoSuchAlgorithmException | NoSuchProviderException ex) {
            Object[] exArgs = {algorithmID, ex.getLocalizedMessage()};
            throw new XMLSignatureException("algorithms.NoSuchAlgorithm", exArgs);
        }
    }

    /** {@inheritDoc} */
    protected void engineSetParameter(AlgorithmParameterSpec params)
        throws XMLSignatureException {
        try {
            this.signatureAlgorithm.setParameter(params);
        } catch (InvalidAlgorithmParameterException ex) {
            throw new XMLSignatureException(ex);
        }
    }

    /** {@inheritDoc} */
    protected boolean engineVerify(byte[] signature) throws XMLSignatureException {
        try {
            return this.signatureAlgorithm.verify(signature);
        } catch (SignatureException ex) {
            throw new XMLSignatureException(ex);
        }
    }

    /** {@inheritDoc} */
    protected void engineInitVerify(Key publicKey) throws XMLSignatureException {
        engineInitVerify(publicKey, this.signatureAlgorithm);
    }

    /** {@inheritDoc} */
    protected byte[] engineSign() throws XMLSignatureException {
        try {
            return this.signatureAlgorithm.sign();
        } catch (SignatureException ex) {
            throw new XMLSignatureException(ex);
        }
    }

    /** {@inheritDoc} */
    protected void engineInitSign(Key privateKey, SecureRandom secureRandom)
        throws XMLSignatureException {
        engineInitSign(privateKey, secureRandom, this.signatureAlgorithm);
    }

    /** {@inheritDoc} */
    protected void engineInitSign(Key privateKey) throws XMLSignatureException {
        engineInitSign(privateKey, (SecureRandom)null);
    }

    /** {@inheritDoc} */
    protected void engineUpdate(byte[] input) throws XMLSignatureException {
        try {
            this.signatureAlgorithm.update(input);
        } catch (SignatureException ex) {
            throw new XMLSignatureException(ex);
        }
    }

    /** {@inheritDoc} */
    protected void engineUpdate(byte input) throws XMLSignatureException {
        try {
            this.signatureAlgorithm.update(input);
        } catch (SignatureException ex) {
            throw new XMLSignatureException(ex);
        }
    }

    /** {@inheritDoc} */
    protected void engineUpdate(byte[] buf, int offset, int len) throws XMLSignatureException {
        try {
            this.signatureAlgorithm.update(buf, offset, len);
        } catch (SignatureException ex) {
            throw new XMLSignatureException(ex);
        }
    }

    /** {@inheritDoc} */
    protected String engineGetJCEAlgorithmString() {
        return this.signatureAlgorithm.getAlgorithm();
    }

    /** {@inheritDoc} */
    protected String engineGetJCEProviderName() {
        return this.signatureAlgorithm.getProvider().getName();
    }

    /** {@inheritDoc} */
    protected void engineSetHMACOutputLength(int HMACOutputLength)
        throws XMLSignatureException {
        throw new XMLSignatureException("algorithms.HMACOutputLengthOnlyForHMAC");
    }

    /** {@inheritDoc} */
    protected void engineInitSign(
        Key signingKey, AlgorithmParameterSpec algorithmParameterSpec
    ) throws XMLSignatureException {
        throw new XMLSignatureException("algorithms.CannotUseAlgorithmParameterSpecOnSphincsPlus");
    }

    public static class SignatureSLHDSASHA2128S extends SignatureBaseSLHDSA
    {
        /**
         * Constructor SignatureSLHDSASHA2128S
         *
         * @throws XMLSignatureException
         */
        public SignatureSLHDSASHA2128S() throws XMLSignatureException {
            super();
        }

        public SignatureSLHDSASHA2128S(Provider provider) throws XMLSignatureException {
            super(provider);
        }

        /** {@inheritDoc} */
        @Override
        public String engineGetURI() {
            return XMLSignature.ALGO_ID_SIGNATURE_SLH_DSA_SHA2_128S;
        }
    }

    public static class SignatureSLHDSASHA2128F extends SignatureBaseSLHDSA
    {
        /**
         * Constructor SignatureSLHDSASHA2128F
         *
         * @throws XMLSignatureException
         */
        public SignatureSLHDSASHA2128F() throws XMLSignatureException {
            super();
        }

        public SignatureSLHDSASHA2128F(Provider provider) throws XMLSignatureException {
            super(provider);
        }

        /** {@inheritDoc} */
        @Override
        public String engineGetURI() {
            return XMLSignature.ALGO_ID_SIGNATURE_SLH_DSA_SHA2_128F;
        }
    }

    public static class SignatureSLHDSASHA2256S extends SignatureBaseSLHDSA
    {
        /**
         * Constructor SignatureSLHDSASHA2256S
         *
         * @throws XMLSignatureException
         */
        public SignatureSLHDSASHA2256S() throws XMLSignatureException {
            super();
        }

        public SignatureSLHDSASHA2256S(Provider provider) throws XMLSignatureException {
            super(provider);
        }

        /** {@inheritDoc} */
        @Override
        public String engineGetURI() {
            return XMLSignature.ALGO_ID_SIGNATURE_SLH_DSA_SHA2_256S;
        }
    }

    public static class SignatureSLHDSASHA2256F extends SignatureBaseSLHDSA
    {
        /**
         * Constructor SignatureSLHDSASHA2256F
         *
         * @throws XMLSignatureException
         */
        public SignatureSLHDSASHA2256F() throws XMLSignatureException {
            super();
        }

        public SignatureSLHDSASHA2256F(Provider provider) throws XMLSignatureException {
            super(provider);
        }

        /** {@inheritDoc} */
        @Override
        public String engineGetURI() {
            return XMLSignature.ALGO_ID_SIGNATURE_SLH_DSA_SHA2_256F;
        }
    }

    public static class SignatureSLHDSASHAKE128S extends SignatureBaseSLHDSA
    {
        /**
         * Constructor SignatureSLHDSASHAKE128S
         *
         * @throws XMLSignatureException
         */
        public SignatureSLHDSASHAKE128S() throws XMLSignatureException {
            super();
        }

        public SignatureSLHDSASHAKE128S(Provider provider) throws XMLSignatureException {
            super(provider);
        }

        /** {@inheritDoc} */
        @Override
        public String engineGetURI() {
            return XMLSignature.ALGO_ID_SIGNATURE_SLH_DSA_SHAKE_128S;
        }
    }

    public static class SignatureSLHDSASHAKE128F extends SignatureBaseSLHDSA
    {
        /**
         * Constructor SignatureSLHDSASHAKE128F
         *
         * @throws XMLSignatureException
         */
        public SignatureSLHDSASHAKE128F() throws XMLSignatureException {
            super();
        }

        public SignatureSLHDSASHAKE128F(Provider provider) throws XMLSignatureException {
            super(provider);
        }

        /** {@inheritDoc} */
        @Override
        public String engineGetURI() {
            return XMLSignature.ALGO_ID_SIGNATURE_SLH_DSA_SHAKE_128F;
        }
    }

    public static class SignatureSLHDSASHAKE256S extends SignatureBaseSLHDSA
    {
        /**
         * Constructor SignatureSLHDSASHAKE256S
         *
         * @throws XMLSignatureException
         */
        public SignatureSLHDSASHAKE256S() throws XMLSignatureException {
            super();
        }

        public SignatureSLHDSASHAKE256S(Provider provider) throws XMLSignatureException {
            super(provider);
        }

        /** {@inheritDoc} */
        @Override
        public String engineGetURI() {
            return XMLSignature.ALGO_ID_SIGNATURE_SLH_DSA_SHAKE_256S;
        }
    }

    public static class SignatureSLHDSASHAKE256F extends SignatureBaseSLHDSA
    {
        /**
         * Constructor SignatureSLHDSASHAKE256F
         *
         * @throws XMLSignatureException
         */
        public SignatureSLHDSASHAKE256F() throws XMLSignatureException {
            super();
        }

        public SignatureSLHDSASHAKE256F(Provider provider) throws XMLSignatureException {
            super(provider);
        }

        /** {@inheritDoc} */
        @Override
        public String engineGetURI() {
            return XMLSignature.ALGO_ID_SIGNATURE_SLH_DSA_SHAKE_256F;
        }
    }
}
