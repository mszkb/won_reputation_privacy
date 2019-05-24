package msz.Reputation;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.Buffer;

/**
 * This is the recieving Bot, in WoN we describe it as the Supplier
 * <p>
 * Alice begins
 * <p>
 * Bob waits for incoming connection of Alice
 * Bob recieves the random Hash from Alice
 * Bob creates also a random Hash and sends it to Alice
 * After sending Bob immediatly signs the hash and sends it with his cert to the Reputation Server
 * Bob waits until the Reputation Server sends a blind signature back (Problem, do not wait)
 * Bob waits for incomming connection of Alice
 * Bob recieves the ReputationToken
 * Bob sends his ReputationToken to Alice
 * Bob sends Alice RepuationToken with rating and the message to the RepuationServer
 */
public class ReputationBotBob extends Thread implements IRepuationBot {

    private static final Log LOG = LogFactory.getLog(ReputationBotBob.class);

    private final int bobPort = 5055;

    private final int otherBotPort;
    private final String otherBotIP;

    private ServerSocket bobSocket;
    private Socket aliceSocket;
    private BufferedReader incommingMessage;
    private PrintWriter outgoingMessage;

    public ReputationBotBob(String otherBotIP, int otherBotPort) {
        // TODO cert of client
        // TODO random hash of client

        this.otherBotIP = otherBotIP;
        this.otherBotPort = otherBotPort;
    }

    /**
     * Initializes Alice Socket, Incomming Message from Alice, Outgoing Message to Alice
     */
    private void waitForAlice() throws IOException {
        this.bobSocket = new ServerSocket(this.bobPort);
        this.aliceSocket = this.bobSocket.accept();
        this.incommingMessage = new BufferedReader(new InputStreamReader(this.aliceSocket.getInputStream()));
        this.outgoingMessage = new PrintWriter(this.aliceSocket.getOutputStream());
    }

    @Override
    public void run() {
        try {
            this.waitForAlice();
            this.commandDispatch();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void commandDispatch() throws IOException {
        String inputLine;

        // TODO we wait for alice random Hash
        while ((inputLine = this.incommingMessage.readLine()) != null) {
            String incoming = "part1 part2";
            String[] parts = incoming.split(" ");

            switch (parts[0]) {
                case "[1]":
                    // Alice has sent the random hash
                    exchangeRandomHash(parts[1]);
                    break;
                case "[2]":
                    this.getBlindSignature();
                    this.createAndExchangeRepuationToken();
                    this.rateTheTransaction();
            }
        }
    }

    @Override
    public void exchangeRandomHash(String randomHash) {
        // TODO we generate a random number hashed

        // TODO we send it to Alice
    }

    /**
     * Overload function which does not take a number as
     * an Input. We use the RNG class for randomize stuff
     */
    public void exchangeRandomHash() {
    }

    @Override
    public void getBlindSignature() {
        // TODO alice is already done and she is waiting for our token

        // TODO we create the reputation token containing our cert and signed random hash from alice

        // TODO send signed hash and certificate of bob to SP

        // TODO wait for SP answer

        // TODO SP answered with blind signature
    }

    @Override
    public void createAndExchangeRepuationToken() {
        // TODO alice is still waiting

        // TODO we send alice the blind signed reputation token

        // TODO alice knows that bob is finished and she rates bob
    }

    @Override
    public void rateTheTransaction() {
        // TODO we don't need an answer from alice anymore

        // TODO connect to SP and send rep token, original hash, reputation and message
    }
}
