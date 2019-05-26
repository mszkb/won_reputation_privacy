package msz.Reputation;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;

/**
 * This is the sending Bot, in WoN this is the Requestor
 * <p>
 * Alice begins
 * <p>
 * Alice connects to Bob
 * Alice sends the random Hash to Bob
 * Alice waits until Bob sends his random Hash
 * Alice signs the hash and sends it with her cert to the RepuationServer
 * Alice waits until the ReputationServer sends a blind signature to her
 * Alice connects to Bob again
 * Alice sends the blind signature to Bob
 * Alice waits until she recieves the ReputationToken from Bob
 * Alice sends Bobs ReputationToken with rating and the message to the ReputationServer
 */
public class ReputationBotAlice implements IRepuationBot {

    private static final Log LOG = LogFactory.getLog(ReputationBotAlice.class);

    private final int bobPort;      // standard 5055
    private final String bobIP;     // standard 127.0.0.1
    private Object bobSocket;
    private BufferedReader incommingMessage;
    private PrintWriter outgoingMessage;

    public ReputationBotAlice(String bobIP, int bobPort) {
        // TODO cert of client
        // TODO random hash of client

        this.bobIP = bobIP;
        this.bobPort = bobPort;
    }

    private void connectToBob() throws IOException {
        this.bobSocket = new Socket(this.bobIP, this.bobPort);
        this.incommingMessage = new BufferedReader(new InputStreamReader(((Socket) this.bobSocket).getInputStream()));
        this.outgoingMessage = new PrintWriter(((Socket) this.bobSocket).getOutputStream());
    }

    @Override
    public void run() {
        try {
            this.connectToBob();            // connect to bob
            this.exchangeRandomHash();      // send random hash to bob
            this.commandDispatch();         // wait for bob and continue protocol
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void commandDispatch() throws IOException {
        String inputLine;

        // we wait for bob's incomming Message
        // bob is now waiting until alice has sent the reputation token
        // when bob recieved the reputation token he knows that alice is
        // ready of recieving a token.
        while ((inputLine = this.incommingMessage.readLine()) != null) {
            // TODO switch case to different commands
            String[] parts = inputLine.split(" ");

            // [1] Alice generates random number, hashes it and sends to Bob
            // [2] Alice got reputation token form bob
            switch (parts[0]) {
                case "[1]":
                    this.getBlindSignature();   // we send cert and signed Hash to SP
                                                // wait for the answer (another socket)
                                                // then create a reputation token
                                                // and send it to Bob
                    this.createAndExchangeRepuationToken();
                                                // loop is over and we wait for bob
                    break;
                case "[2]":
                    // bob answered with his  reputationtoken
                    // now we are obligated to rate the transaction
                    // open another socket to the SP with token, original hash, message and rating
                    this.rateTheTransaction();
                    break;
            }
        }
    }

    @Override
    public void exchangeRandomHash(String randomHash) {
        // TODO send hashed number to bob

        // TODO wait for Bobs answer with his hash
    }

    /**
     * Overload function which does not take a number as
     * an Input. We use the RNG class for randomize stuff
     */
    public void exchangeRandomHash() {
        // TODO send hashed number to bob

        // TODO wait for Bobs answer with his hash
    }

    @Override
    public void getBlindSignature() {
        // TODO sign the hash number from bob

        // TODO connect to SP with socket

        // TODO send signed hash and certificate of alice to SP

        // TODO wait for SP answer

        // TODO SP answered with blind signature
    }

    @Override
    public void createAndExchangeRepuationToken() {
        // TODO bob is still waiting

        // TODO we send bob the blind signed reputation token

        // TODO bob knows that alice is ready recieving a rep token
    }

    @Override
    public void rateTheTransaction() {
        // TODO we got the reputation token from bo

        // TODO connect to SP and send rep token, original hash, reputation and message
    }
}
