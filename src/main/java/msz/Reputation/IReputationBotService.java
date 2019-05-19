package msz.Reputation;

import msz.Message.Reputationtoken;

import java.util.List;

public class IReputationBotService extends Thread implements IReputationServer {

    public IReputationBotService() {

    }

    @Override
    public void run() {

    }

    @Override
    public void addRating(int forUser, float rating, String message, byte[] blindToken, byte[] originalHash) throws Exception {

    }

    @Override
    public byte[] blindAndSign(Reputationtoken token) {
        return new byte[0];
    }

    @Override
    public float getCurrentRating(int userId) {
        return 0;
    }

    @Override
    public List<Reputation> getReputations(int userId) {
        return null;
    }
}
