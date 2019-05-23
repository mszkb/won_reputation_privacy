package msz.Reputation;

import msz.Message.Reputationtoken;
import msz.Signer.BlindSignature;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

public class ReputationService extends Thread implements IReputationServer {
    private final ReputationStore reputationStore;

    // TODO replace reputation hashmap with the reference to the store
    private ConcurrentHashMap<Integer, List<Reputation>> reputation = new ConcurrentHashMap<Integer, List<Reputation>>();
    private BlindSignature blindingHelper = new BlindSignature();

    public ReputationService(ReputationStore reputationStore) {
        this.reputationStore = reputationStore;
    }

    @Override
    public void run() {

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
        List<Reputation> reputationList = this.reputation.get(userId);
        float rating = 0;

        for(Reputation reputation : reputationList) {
            rating += reputation.getRating();
        }

        float avgRating = rating / reputationList.size();

        return avgRating;
    }

    @Override
    public List<Reputation> getReputations(int userId) {
        return this.reputation.get(userId);
    }
}
