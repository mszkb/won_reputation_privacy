package msz.Reputation;

import msz.Signer.BlindSignature;

public class ReputationStore {
    private BlindSignature blindSignature = new BlindSignature();

    public ReputationStore() {

    }

    public BlindSignature getBlindingHelper() {
        return this.blindSignature;
    }
}
