package msz.bakk.protocol.Reputation;

import msz.bakk.protocol.Signer.BlindSignature;

public class ReputationStore {
    private BlindSignature blindSignature = new BlindSignature();

    public ReputationStore() {

    }

    public BlindSignature getBlindingHelper() {
        return this.blindSignature;
    }
}
