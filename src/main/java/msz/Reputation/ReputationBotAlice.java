package msz.Reputation;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * This is the sending Bot, in WoN this is the Requestor
 *
 * Alice begins
 *
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
public class ReputationBotAlice extends Thread implements IRepuationBot {

    private static final Log LOG = LogFactory.getLog(ReputationBotAlice.class);

    private final int otherBotPort;
    private final String otherBotIP;

    public ReputationBotAlice(String otherBotIP, int otherBotPort) {
        // TODO cert of client
        // TODO random hash of client

        this.otherBotIP = otherBotIP;
        this.otherBotPort = otherBotPort;
    }

    @Override
    public void run() {
        // TODO connect to Bob


        // TODO switch case to different commands
        String incoming = "part1 part2";
        String[] parts = incoming.split(" ");

        // TODO Start connection of other bot in seperateThread

        switch (parts[0]) {
            case "randomHash":
                exchangeRandomHash(parts[1]);
        }
    }

    @Override
    public void exchangeRandomHash(String randomHash) {
        // TODO
    }

    @Override
    public void getBlindSignature() {

    }

    @Override
    public void createAndExchangeRepuationToken() {

    }

    @Override
    public void rateTheTransaction() {

    }

    private class OtherBotConnectionHandler extends Thread {
        public OtherBotConnectionHandler() {

        }

        public void run() {
            // TODO switch case to different commands
            String incoming = "part1 part2";
            String[] parts = incoming.split(" ");

            // TODO Start connection of other bot in seperateThread

            switch (parts[0]) {
                case "randomHash":
            }
        }
    }
}
