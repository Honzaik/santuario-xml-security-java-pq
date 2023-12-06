package org.apache.xml.security.utils.hybrid;

import java.security.spec.AlgorithmParameterSpec;
import java.util.ArrayList;
import java.util.List;

public class HybridAlgorithmSpec implements AlgorithmParameterSpec {

    private final List<AlgorithmParameterSpec> componentAlgorithms;

    public HybridAlgorithmSpec () {
        this(new ArrayList<>());
    }

    public HybridAlgorithmSpec (List<AlgorithmParameterSpec> componentAlgorithms) {
        this.componentAlgorithms = componentAlgorithms;
    }

    public List<AlgorithmParameterSpec> getComponentAlgorithms() {
        return this.componentAlgorithms;
    }

    public void addComponentAlgorithm(AlgorithmParameterSpec algorithmParameterSpec) {
        this.componentAlgorithms.add(algorithmParameterSpec);
    }

    public int getComponentCount() {
        return this.componentAlgorithms.size();
    }
}
