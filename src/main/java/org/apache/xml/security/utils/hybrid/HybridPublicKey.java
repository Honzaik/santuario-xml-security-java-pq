package org.apache.xml.security.utils.hybrid;

import java.io.ByteArrayOutputStream;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

public class HybridPublicKey implements PublicKey {

    private final List<PublicKey> componentPublicKeys; //to keep the right order of components
//    private final HashMap<String, PublicKey> algorithmPublicKeyMap;

    public HybridPublicKey () {
        this(new ArrayList<>());
    }

    public HybridPublicKey (List<PublicKey> componentPublicKeys) {
        this.componentPublicKeys = componentPublicKeys;
//        this.algorithmPublicKeyMap = new HashMap<>();
//        for (PublicKey key : this.componentPublicKeys) {
//            this.algorithmPublicKeyMap.put(HybridConstants.keyAlgorithmToSignatureAlgorithmMap.get(key.getAlgorithm()), key);
//        }
    }

//    public HashMap<String, PublicKey> getAlgorithmPublicKeyMap() {
//        return this.algorithmPublicKeyMap;
//    }

    public List<PublicKey> getComponentPublicKeys() {
        return componentPublicKeys;
    }

    @Override
    public String getAlgorithm() {
        String hybridAlgorithmName = "";
        for (PublicKey key : this.componentPublicKeys) {
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

        for (PublicKey key : this.componentPublicKeys) {
            expectedByteSize += HybridConstants.publicKeySizes.get(key.getAlgorithm());
            bs.writeBytes(key.getEncoded());
        }

        byte[] encodedKey = bs.toByteArray();

        if (encodedKey.length != expectedByteSize) {
            throw new RuntimeException("Invalid hybrid public key");
        }

        return encodedKey;
    }
}
