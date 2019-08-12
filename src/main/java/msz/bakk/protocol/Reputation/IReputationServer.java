package msz.bakk.protocol.Reputation;

import msz.bakk.protocol.Message.Reputationtoken;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
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
public interface IReputationServer extends Runnable {
    /**
     * Adding the rating and a comment for the userID
     * Only if there is a valid token the rating is added
     *  @param forUser
     * @param rating
     * @param message
     * @param blindRepuationToken
     * @param originalHash
     */
    void addRating(String forUser, String rating, String message, String blindRepuationToken, String originalHash, String originalReputationToken) throws Exception;
    String signBlind(String blindedToken) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException;
    float getCurrentRating(int userId);
    List<Reputation> getReputations(int userId);
}
