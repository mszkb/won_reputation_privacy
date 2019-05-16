package msz.Reputation;

import msz.Message.Reputationtoken;
import msz.Signer.BlindSignature;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

public class ReputationService implements RepuationServer {
    private HashMap<Integer, List<Reputation>> reputation = new HashMap<>();
    private BlindSignature blindingHelper = new BlindSignature();

    public ReputationService() {
    }

    @Override
    public void addRating(int forUser, float rating, String message, byte[] blindRepuationToken, byte[] originalHash) throws Exception {
        if(this.blindingHelper.verify(blindRepuationToken, originalHash)) {
            throw new Exception("Reputationtoken is not valid");
        }

        if (this.reputation.containsKey(forUser)) {
            List<Reputation> list = this.reputation.get(forUser);
            list.add(new Reputation(rating, message, blindRepuationToken));
        } else {
            List<Reputation> newList = new ArrayList<>();
            newList.add(new Reputation(rating, message, blindRepuationToken));
            this.reputation.put(forUser, newList);
        }
    }

    @Override
    public byte[] blindAndSign(Reputationtoken token) {
        return this.blindingHelper.blindAndSign(token.getBytes());
    }

    @Override
    public float getCurrentRating(int userId) {
        return 0;
    }

    @Override
    public List<Reputation> getReputations() {
        return null;
    }
}
