package org.apache.xml.security.utils.hybrid;

import java.io.ByteArrayOutputStream;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

public class HybridPrivateKey implements PrivateKey {

    private final List<PrivateKey> componentPrivateKeys; //to keep the right order of components
    //private final HashMap<String, PrivateKey> algorithmPrivateKeyMap;

    public HybridPrivateKey () {
        this(new ArrayList<>());
    }

    public HybridPrivateKey (List<PrivateKey> componentPrivateKeys) {
        this.componentPrivateKeys = componentPrivateKeys;
//        this.algorithmPrivateKeyMap = new HashMap<>();
//        for (PrivateKey key : this.componentPrivateKeys) {
//            this.algorithmPrivateKeyMap.put(HybridConstants.keyAlgorithmToSignatureAlgorithmMap.get(key.getAlgorithm()), key);
//        }
    }

//    public HashMap<String, PrivateKey> getAlgorithmPrivateKeyMap() {
//        return this.algorithmPrivateKeyMap;
//    }

    public List<PrivateKey> getComponentPrivateKeys() {
        return componentPrivateKeys;
    }

    @Override
    public String getAlgorithm() {
        String hybridAlgorithmName = "";
        for (PrivateKey key : this.componentPrivateKeys) {
            hybridAlgorithmName += key.getAlgorithm() + "|";
        }

        if (!hybridAlgorithmName.isEmpty()) {
            hybridAlgorithmName = hybridAlgorithmName.substring(0, hybridAlgorithmName.length() - 1);
        }

        return hybridAlgorithmName;
    }

    @Override
    public String getFormat() {
        return null;
    }

    @Override
    public byte[] getEncoded() {
        int expectedByteSize = 0;
        ByteArrayOutputStream bs = new ByteArrayOutputStream();

        for (PrivateKey key : this.componentPrivateKeys) {
            expectedByteSize += HybridConstants.privateKeySizes.get(key.getAlgorithm());
            bs.writeBytes(key.getEncoded());
        }

        byte[] encodedKey = bs.toByteArray();

        if (encodedKey.length != expectedByteSize) {
            throw new RuntimeException("Invalid hybrid private key");
        }

        return encodedKey;
    }
}
