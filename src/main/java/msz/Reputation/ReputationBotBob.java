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
        this.bobSocket = new ServerSocket();
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
        while ((inputLine = this.incommingMessage.readLine()) != null) {
            // TODO switch case to different commands
            String incoming = "part1 part2";
            String[] parts = incoming.split(" ");

            // TODO Start connection of other bot in seperateThread

            switch (parts[0]) {
                case "randomHash":
                    exchangeRandomHash(parts[1]);
            }
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
