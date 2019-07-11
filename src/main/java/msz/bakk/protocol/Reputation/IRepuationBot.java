package msz.bakk.protocol.Reputation;

public interface IRepuationBot extends Runnable {
    /**
     * Creates a random send_randomhash and sends it to the other bot
     * This method blocks until we get the random send_randomhash from the other bot
     */
    void exchangeRandomHash(String randomHash);

    /**
     * Sends cert and signature of send_randomhash to the server and recieves an blindsignature of that
     */
    void getBlindSignature();

    /**
     * Creates an reputation token and sends it to other bot
     * This method blocks until we get the token from the other bot
     */
    void exchangeRepuationToken();

    /**
     * With the reputationtoken we can send it to the SP with the rating and a comment
     */
    void rateTheTransaction();
}
