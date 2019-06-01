package msz.Reputation;

import msz.Message.Reputationtoken;

/**
 * A reputation token holds the rating as a float (a few people vote 3.5 stars for example)
 *                          the comment
 *                          the blindedReputationtoken
 * If you want to reveal your realname you can use the method 'revealReal' and you will see the
 * comment with the real credentials. Only if both Users want that.
 */
public class Reputation {

    private String fromUser = "anonymous"; // username are optional
    private final byte[] blindedReputationtoken;
    private final Reputationtoken reputationToken;
    private final float rating;
    private final String comment;

    public Reputation(float rating, String comment, byte[] blindedReputationtoken, Reputationtoken reputationToken) {
        this.rating = rating;
        this.comment = comment;
        this.blindedReputationtoken = blindedReputationtoken;
        this.reputationToken = reputationToken;
    }

    public void revealReal(String realName) {
        this.fromUser = realName;
    }

    public String getComment() {
        return comment;
    }

    public float getRating() {
        return rating;
    }

    /**
     * The repuationtoken is blinded, only the repuationserver is able
     * to unblind and verify it.
     * So: contact a reputation bot and let the bot verify the token
     */
    public byte[] getBlindedReputationtoken() {
        return blindedReputationtoken;
    }
}
