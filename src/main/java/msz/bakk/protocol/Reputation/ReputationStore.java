package msz.bakk.protocol.Reputation;

import msz.bakk.protocol.Utils.BlindSignatureUtils;

public class ReputationStore {
    private BlindSignatureUtils blindSignature = new BlindSignatureUtils();

    public ReputationStore() {

    }

    public BlindSignatureUtils getBlindingHelper() {
        return this.blindSignature;
    }
}
