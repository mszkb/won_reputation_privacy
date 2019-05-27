package msz.Reputation;

import msz.Message.Certificate;
import msz.Message.Reputationtoken;
import msz.Utils.ECUtils;
import msz.Utils.HashUtils;
import msz.Utils.RSAUtils;
import msz.Utils.WrappedSocket;
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
    private String blindedReputationToken;

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
                    this.blindedReputationToken = parts[2];
                    LOG.info("we got the reputation token");
                    this.getBlindSignature();
                    this.createAndExchangeRepuationToken();
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
        // TODO alice is already done and she is waiting for our token
        byte[] signedHashBob = null;
        try {
            signedHashBob = RSAUtils.signString(this.bobKeyPair.getPrivate(), randomHashFromAlice);
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            e.printStackTrace();
        }

        // TODO we create the reputation token containing our cert and signed random hash from alice
        Reputationtoken tokenForAlice = new Reputationtoken(certificateBob, signedHashBob);

        // TODO send signed hash and certificate of bob to SP
//        byte[] blindedReputationToken = this.blindSigner.blindAndSign(tokenForBob.getBytes());
        WrappedSocket spSocket = new WrappedSocket("localhost", reputationServicePort);
        spSocket.writeOut("blind " + tokenForAlice);
        String blinded = "";
        try {
            // TODO wait for SP answer
            blinded = spSocket.readIn();
        } catch (IOException e) {
            e.printStackTrace();
        }
        spSocket.writeOut("bye");
        spSocket.close();

        this.outMsgAlice.println(blinded);
    }

    @Override
    public void createAndExchangeRepuationToken() {
        // TODO alice is still waiting

        // TODO we send alice the blind signed reputation token

        // TODO alice knows that bob is finished and she rates bob
        this.outMsgAlice.println("bla\n");
    }

    @Override
    public void rateTheTransaction() {
        // TODO we don't need an answer from alice anymore

        // TODO connect to SP and send rep token, original hash, reputation and message
    }
}
