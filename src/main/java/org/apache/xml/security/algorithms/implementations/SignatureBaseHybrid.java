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
import org.apache.xml.security.utils.hybrid.HybridAlgorithmSpec;
import org.apache.xml.security.utils.hybrid.HybridConstants;
import org.apache.xml.security.utils.hybrid.HybridPrivateKey;
import org.apache.xml.security.utils.hybrid.HybridPublicKey;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.System.Logger;
import java.lang.System.Logger.Level;
import java.security.*;
import java.security.interfaces.RSAKey;
import java.security.spec.AlgorithmParameterSpec;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;


public abstract class SignatureBaseHybrid extends SignatureAlgorithmSpi {
    private static final Logger LOG = System.getLogger(SignatureBaseHybrid.class.getName());

    /** Field algorithm */
    private final List<Signature> signatureAlgorithms;
    private final List<String> keyParameters; //at position i there is parameter set ID corresponding to signature algorithm at i used in HybridConstants

    /**
     * Constructor SignatureBaseHybrid
     *
     * @throws XMLSignatureException
     */
    public SignatureBaseHybrid() throws XMLSignatureException {
        this(null);
    }

    public SignatureBaseHybrid(Provider provider) throws XMLSignatureException {
        String hybridAlgorithmID = JCEMapper.translateURItoJCEID(this.engineGetURI());

        List<String> componentAlgorithmIds = JCEMapper.getComponentAlgorithmIds(hybridAlgorithmID);
        this.signatureAlgorithms = new ArrayList<>();
        this.keyParameters = new ArrayList<>();

        LOG.log(Level.INFO, "Created SignatureBaseHybrid using {0}", hybridAlgorithmID);
        LOG.log(Level.INFO, "It has {0} components", componentAlgorithmIds.size());

        try {
            if (provider == null) {
                String providerId = JCEMapper.getProviderId();
                if (providerId == null) {
                    for (String algorithmID : componentAlgorithmIds) {
                        this.signatureAlgorithms.add(Signature.getInstance(algorithmID));
                    }
                } else {
                    for (String algorithmID : componentAlgorithmIds) {
                        this.signatureAlgorithms.add(Signature.getInstance(algorithmID, providerId));
                    }
                }

            } else {
                for (String algorithmID : componentAlgorithmIds) {
                    this.signatureAlgorithms.add(Signature.getInstance(algorithmID, provider));
                }
            }
        } catch (NoSuchAlgorithmException | NoSuchProviderException ex) {
            Object[] exArgs = {hybridAlgorithmID, ex.getLocalizedMessage()};
            throw new XMLSignatureException("algorithms.NoSuchAlgorithm", exArgs);
        }
    }

    /** {@inheritDoc} */
    protected void engineSetParameter(AlgorithmParameterSpec params)
        throws XMLSignatureException {

        if (!(params instanceof HybridAlgorithmSpec)) {
            throw new XMLSignatureException("algorithms.UnsupportedAlgorithmParameterSpec");
        }

        List<AlgorithmParameterSpec> hybridAlgorithmSpec = ((HybridAlgorithmSpec) params).getComponentAlgorithms();

        try {
            for (int i = 0; i < this.signatureAlgorithms.size(); i++) {
                this.signatureAlgorithms.get(i).setParameter(hybridAlgorithmSpec.get(i));
            }
        } catch (InvalidAlgorithmParameterException ex) {
            throw new XMLSignatureException(ex);
        }
    }

    /** {@inheritDoc} */
    protected boolean engineVerify(byte[] signatureBytes) throws XMLSignatureException {
        try {
            ByteArrayInputStream is = new ByteArrayInputStream(signatureBytes);
            for (int i = 0; i < this.signatureAlgorithms.size(); i++) {
                int signatureByteSize = HybridConstants.signatureSizes.get(this.keyParameters.get(i));
                if (!this.signatureAlgorithms.get(i).verify(is.readNBytes(signatureByteSize))) {
                    throw new RuntimeException("Invalid signature");
                }
            }
        } catch (SignatureException ex) {
            throw new XMLSignatureException(ex);
        } catch (RuntimeException | IOException ex) {
            return false;
        } return true; // if not exception
    }

    /** {@inheritDoc} */
    protected void engineInitVerify(Key publicKey) throws XMLSignatureException {
        if (!(publicKey instanceof HybridPublicKey)) {
            throw new XMLSignatureException("algorithms.UnsupportedPublicKey");
        }

        HybridPublicKey hybridPublicKey = (HybridPublicKey)publicKey;

        try {
            for (int i = 0; i < this.signatureAlgorithms.size(); i++) {
                PublicKey key = hybridPublicKey.getComponentPublicKeys().get(i);
                addKeyParameterInfo(key);
                engineInitVerify(key, this.signatureAlgorithms.get(i));
            }
        } catch (NullPointerException ex) {
            throw new XMLSignatureException(ex);
        }
    }

    /** {@inheritDoc} */
    protected byte[] engineSign() throws XMLSignatureException {
        try {
            int expectedByteSize = 0;
            ByteArrayOutputStream signatureOS = new ByteArrayOutputStream();
            for (int i = 0; i < this.signatureAlgorithms.size() ; i++) {
                expectedByteSize += HybridConstants.signatureSizes.get(this.keyParameters.get(i));
                byte[] sig = this.signatureAlgorithms.get(i).sign();
                LOG.log(Level.INFO, "{0} size {1} bytes", this.keyParameters.get(i), sig.length);
                signatureOS.writeBytes(sig);
            }

            byte[] signatureBytes = signatureOS.toByteArray();

            if (signatureBytes.length != expectedByteSize) {
                throw new SignatureException("Hybrid signature has unexpected length. Real: " + signatureBytes.length +", expected: " + expectedByteSize);
            }

            return signatureBytes;
        } catch (SignatureException ex) {
            throw new XMLSignatureException(ex);
        }
    }

    /** {@inheritDoc} */
    protected void engineInitSign(Key privateKey, SecureRandom secureRandom)
        throws XMLSignatureException {
        if (!(privateKey instanceof HybridPrivateKey)) {
            throw new XMLSignatureException("algorithms.UnsupportedPrivateKey");
        }

        HybridPrivateKey hybridPrivateKey = (HybridPrivateKey)privateKey;

        try {
            for (int i = 0; i < this.signatureAlgorithms.size(); i++) {
                PrivateKey key = hybridPrivateKey.getComponentPrivateKeys().get(i);
                addKeyParameterInfo(key);
                engineInitSign(key, secureRandom, this.signatureAlgorithms.get(i));
            }
        } catch (NullPointerException ex) {
            throw new XMLSignatureException(ex);
        }
    }

    /** {@inheritDoc} */
    protected void engineInitSign(Key privateKey) throws XMLSignatureException {
        engineInitSign(privateKey, (SecureRandom)null);
    }

    /** {@inheritDoc} */
    protected void engineUpdate(byte[] input) throws XMLSignatureException {
        try {
            for (Signature signature : this.signatureAlgorithms) {
                signature.update(input);
            }
        } catch (SignatureException ex) {
            throw new XMLSignatureException(ex);
        }
    }

    /** {@inheritDoc} */
    protected void engineUpdate(byte input) throws XMLSignatureException {
        try {
            for (Signature signature : this.signatureAlgorithms) {
                signature.update(input);
            }
        } catch (SignatureException ex) {
            throw new XMLSignatureException(ex);
        }
    }

    /** {@inheritDoc} */
    protected void engineUpdate(byte[] buf, int offset, int len) throws XMLSignatureException {
        try {
            for (Signature signature : this.signatureAlgorithms) {
                signature.update(buf, offset, len);
            }
        } catch (SignatureException ex) {
            throw new XMLSignatureException(ex);
        }
    }

    /** {@inheritDoc} */
    protected String engineGetJCEAlgorithmString() {
        String hybridAlgorithmName = "";
        for (Signature signature : this.signatureAlgorithms) {
            hybridAlgorithmName += signature.getAlgorithm() + "|";
        }

        if (!hybridAlgorithmName.isEmpty()) {
            hybridAlgorithmName = hybridAlgorithmName.substring(0, hybridAlgorithmName.length() - 1);
        }

        return hybridAlgorithmName;
    }

    /** {@inheritDoc} */
    protected String engineGetJCEProviderName() {
        String hybridAlgorithmProviderNames = "";
        for (Signature signature : this.signatureAlgorithms) {
            hybridAlgorithmProviderNames += signature.getProvider().getName() + "|";
        }

        if (!hybridAlgorithmProviderNames.isEmpty()) {
            hybridAlgorithmProviderNames = hybridAlgorithmProviderNames.substring(0, hybridAlgorithmProviderNames.length() - 1);
        }

        return hybridAlgorithmProviderNames;
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
        throw new XMLSignatureException("algorithms.CannotUseAlgorithmParameterSpecOnHybrid");
    }

    private void addKeyParameterInfo(Key key) {
        LOG.log(Level.INFO, key.getAlgorithm());
        if (key instanceof RSAKey) {
            RSAKey rsaKey = (RSAKey) key;
            LOG.log(Level.INFO, "rsa params " + key.getAlgorithm() + "-" + rsaKey.getModulus().bitLength());
            this.keyParameters.add(key.getAlgorithm() + "-" + rsaKey.getModulus().bitLength());
        } else {
            this.keyParameters.add(key.getAlgorithm());
        }
    }

    public static class SignatureEd25519Dilithium extends SignatureBaseHybrid {
        /**
         * Constructor SignatureEd25519Dilithium
         *
         * @throws XMLSignatureException
         */
        public SignatureEd25519Dilithium() throws XMLSignatureException {
            super();
        }

        public SignatureEd25519Dilithium(Provider provider) throws XMLSignatureException {
            super(provider);
        }

        /** {@inheritDoc} */
        @Override
        public String engineGetURI() {
            return XMLSignature.ALGO_ID_SIGNATURE_HYBRID_EDDSA_ED25519_DILITHIUM;
        }
    }

    public static class SignatureRSASHA256Dilithium extends SignatureBaseHybrid {
        /**
         * Constructor SignatureRSASHA256Dilithium
         *
         * @throws XMLSignatureException
         */
        public SignatureRSASHA256Dilithium() throws XMLSignatureException {
            super();
        }

        public SignatureRSASHA256Dilithium(Provider provider) throws XMLSignatureException {
            super(provider);
        }

        /** {@inheritDoc} */
        @Override
        public String engineGetURI() {
            return XMLSignature.ALGO_ID_SIGNATURE_HYBRID_RSA_SHA256_DILITHIUM;
        }
    }
}
