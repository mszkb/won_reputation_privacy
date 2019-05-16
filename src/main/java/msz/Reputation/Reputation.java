package msz.Reputation;

import msz.Message.Reputationtoken;

/**
 * A reputation token holds the rating as a float (a few people vote 3.5 stars for example)
 *                          the comment
 *                          the reputationtoken
 * If you want to reveal your realname you can use the method 'revealReal' and you will see the
 * comment with the real credentials. Only if both Users want that.
 */
public class Reputation {

    private String fromReal;
    private final Reputationtoken reputationtoken;
    private final float rating;
    private final String comment;

    public Reputation(float rating, String comment, byte[] reputationtoken) {
        this.rating = rating;
        this.comment = comment;
        this.reputationtoken = reputationtoken;
    }

    public void revealReal(String realName) {
        this.fromReal = realName;
    }

    public String getComment() {
        return comment;
    }

    public float getRating() {
        return rating;
    }

    public Reputationtoken getReputationtoken() {
        return reputationtoken;
    }
}
