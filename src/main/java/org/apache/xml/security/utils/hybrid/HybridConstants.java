package org.apache.xml.security.utils.hybrid;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.HashMap;

public final class HybridConstants {

    public static HashMap<String, Integer> signatureSizes = new HashMap<>();
    static {
        signatureSizes.put("Ed25519", 64);
        signatureSizes.put("DILITHIUM2", 2420);
        signatureSizes.put("RSA-2048", 256);
    }

    public static HashMap<String, Integer> publicKeySizes = new HashMap<>();
    static {
        publicKeySizes.put("Ed25519", 32);
        publicKeySizes.put("DILITHIUM2", 1312);
        publicKeySizes.put("RSA-2048", 1312);
    }

    public static HashMap<String, Integer> privateKeySizes = new HashMap<>();
    static {
        privateKeySizes.put("Ed25519", 32);
        privateKeySizes.put("DILITHIUM2", 2528);
        privateKeySizes.put("RSA-2048", 2528);
    }

    public static HashMap<String, String> keyAlgorithmToSignatureAlgorithmMap = new HashMap<>();
    static {
        keyAlgorithmToSignatureAlgorithmMap.put("Ed25519", "Ed25519");
        keyAlgorithmToSignatureAlgorithmMap.put("DILITHIUM2", "Dilithium");
        keyAlgorithmToSignatureAlgorithmMap.put("RSA", "RSA");
    }

    private HybridConstants() {
        // we don't allow instantiation
    }

}
