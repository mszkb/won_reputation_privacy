package msz.Reputation;

import msz.Message.Reputationtoken;

import java.util.List;

/**
 * The reputation server is the third party which holds all the reputation of all users.
 * You can only communicate with this service via bots which are registered in the system.
 *
 * Funcationality:
 * - Adding new reputation
 * - Grabbing current AVG reputation of a user when creating an ACL token
 * - Getting a list of comments and rating as a list
 * - create blindsignatures of reputation token
 */
public interface ReputationServer {
    /**
     * Adding the rating and a comment for the userID
     * Only if there is a valid token the rating is added
     *
     * @param forUser
     * @param rating
     * @param message
     * @param blindToken
     * @param originalHash
     */
    void addRating(int forUser, float rating, String message, byte[] blindToken, byte[] originalHash) throws Exception;
    byte[] blindAndSign(Reputationtoken token);
    float getCurrentRating(int userId);
    List<Reputation> getReputations(int userId);
}
