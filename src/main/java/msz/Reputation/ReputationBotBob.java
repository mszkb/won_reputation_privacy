package msz.Reputation;

import msz.Message.Certificate;
import msz.Message.Reputationtoken;
import msz.Utils.*;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;

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
public class ReputationBotBob implements IRepuationBot {

    private static final Log LOG = LogFactory.getLog(ReputationBotBob.class);

    private final int reputationServicePort = 5555;

    private final int bobPort = 5055;
    private KeyPair bobKeyPair = null;
    private Certificate certificateBob;

    private ServerSocket bobSocket;
    private Socket aliceSocket;
    private BufferedReader incMsgAlice;
    private PrintWriter outMsgAlice;

    private BufferedReader incMsgWonNode;
    private PrintWriter outMsgWonNode;

    private String randomHashFromAlice = null;
    private String randomHashBobOriginal = null;
    private byte[] blindedReputationToken;
    private Reputationtoken reputationTokenFromAlice;

    private Reputationtoken originalTokenForAlice;
    private String blindedTokenForAlice;

    public ReputationBotBob(Socket socket, Certificate certificateBob) {
        try {
            this.bobKeyPair = ECUtils.generateKeyPair();
            this.incMsgWonNode = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            this.outMsgWonNode = new PrintWriter(socket.getOutputStream());
        } catch (IOException | InvalidAlgorithmParameterException | NoSuchProviderException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        this.certificateBob = certificateBob;
    }

    public ReputationBotBob(InputStream incMsgWonNode, OutputStream outMsgWonNode, Certificate certificateBob) {
        try {
            this.bobKeyPair = ECUtils.generateKeyPair();
        } catch (InvalidAlgorithmParameterException | NoSuchProviderException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        this.incMsgWonNode = new BufferedReader(new InputStreamReader(incMsgWonNode));
        this.outMsgWonNode = new PrintWriter(outMsgWonNode);
        this.certificateBob = certificateBob;
    }

    /**
     * Initializes Alice Socket, Incomming Message from Alice, Outgoing Message to Alice
     */
    private void waitForAlice() throws IOException {
        LOG.info("Wait for Alice, on port " + this.bobPort);

        this.bobSocket = new ServerSocket(this.bobPort);
        this.aliceSocket = this.bobSocket.accept();

        LOG.info("Connection accepted");

        this.incMsgAlice = new BufferedReader(new InputStreamReader(this.aliceSocket.getInputStream()));
        this.outMsgAlice = new PrintWriter(this.aliceSocket.getOutputStream(), true);

        this.outMsgAlice.println("hi");
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

        LOG.info("We wait for a message");
        while ((inputLine = this.incMsgAlice.readLine()) != null) {
            LOG.info("Alice wrote something: " + inputLine);
            String[] parts = inputLine.split(" ");

            switch (parts[0]) {
                case "[1]":
                    LOG.info("we get random hash from alice");
                    // Alice has sent the random hash
                    exchangeRandomHash(parts[1]);
                    break;
                case "[2]":
                    this.blindedReputationToken = MessageUtils.decodeToBytes(parts[1]);
                    this.reputationTokenFromAlice = MessageUtils.decodeRT(parts[2]);
                    LOG.info("Bob got the reputation token");
                    this.getBlindSignature();
                    this.exchangeRepuationToken();
                    this.rateTheTransaction();
            }
        }
    }

    @Override
    public void exchangeRandomHash(String randomHashFromAlice) {
        this.randomHashFromAlice = randomHashFromAlice;

        String randomHashBob = null;
        try {
            randomHashBob = HashUtils.generateRandomHash();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        this.randomHashBobOriginal = randomHashBob;
        this.outMsgAlice.println("[1] " + randomHashBob);
        this.outMsgAlice.flush();
    }

    /**
     * Overload function which does not take a number as
     * an Input. We use the RNG class for randomize stuff
     */
    public void exchangeRandomHash() {

    }

    @Override
    public void getBlindSignature() {
        // alice is already done and she is waiting for our token

        byte[] signedHashAlice = null;
        try {
            signedHashAlice = RSAUtils.signString(this.bobKeyPair.getPrivate(), randomHashFromAlice);
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            e.printStackTrace();
        }
        this.originalTokenForAlice = new Reputationtoken(certificateBob, signedHashAlice);
        try {
            this.blindedTokenForAlice = blindTokenForAlice(originalTokenForAlice);
            Thread.sleep(2000);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private String blindTokenForAlice(Reputationtoken tokenForAlice) throws IOException {
        // We connect to the Reputationservice for blinding our token for alice

        WrappedSocket spSocket = new WrappedSocket("localhost", reputationServicePort, true);
        spSocket.writeOut("blind " + MessageUtils.toString(tokenForAlice));
        String blinded = spSocket.readIn();
        spSocket.writeOut("bye");
        spSocket.close();

        return blinded;
    }

    @Override
    public void exchangeRepuationToken() {
        // We send the blinded Reputation Token and the original base64 encoded reputation token to alice

        String encodedTokenForAlice = null;
        try {
            encodedTokenForAlice = MessageUtils.toString(this.originalTokenForAlice);
        } catch (IOException e) {
            e.printStackTrace();
        }
        String messageBack = "[2] " + this.blindedTokenForAlice + " " + encodedTokenForAlice;
        this.outMsgAlice.println(messageBack);
    }

    @Override
    public void rateTheTransaction() {
        // TODO we don't need an answer from alice anymore

        // TODO connect to SP and send rep token, original hash, reputation and message

        // Atlast we write alice that everything is fine
        this.outMsgAlice.println("everything is ok");
    }
}
