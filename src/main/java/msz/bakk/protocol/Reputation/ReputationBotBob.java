package msz.bakk.protocol.Reputation;

import msz.bakk.protocol.Message.Certificate;
import msz.bakk.protocol.Message.Reputationtoken;
import msz.bakk.protocol.Utils.*;
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
 * After sending Bob immediatly signs the send_randomhash and sends it with his cert to the Reputation Server
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
    private boolean standalone = true;
    private KeyPair bobKeyPair = null;
    private Certificate certificateBob;

    private ServerSocket bobSocket;
    private Socket aliceSocket;
    private BufferedReader incMsgAlice;
    private PrintWriter outMsgAlice;

    private BufferedReader incMsgWonNode;
    private PrintWriter outMsgWonNode;

    private String randomHashBobOriginal = null;

    private String randomHashFromAlice = null;
    private String blindedReputationTokenFromAlice;
    private Reputationtoken reputationTokenFromAlice;
    private String encodedReputationTokenFromAlice;

    private Reputationtoken originalTokenForAlice;
    private String blindedTokenForAlice;

    public ReputationBotBob(Socket socket, Certificate certificateBob) {
        try {
            this.bobKeyPair = ECUtils.generateKeyPair();
            this.incMsgWonNode = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            this.outMsgWonNode = new PrintWriter(socket.getOutputStream(), true);
        } catch (IOException e) {
            e.printStackTrace();
        }

        this.certificateBob = certificateBob;
    }

    public ReputationBotBob(InputStream incMsgWonNode, OutputStream outMsgWonNode, Certificate certificateBob) {
        this.bobKeyPair = ECUtils.generateKeyPair();
        this.incMsgWonNode = new BufferedReader(new InputStreamReader(incMsgWonNode));
        this.outMsgWonNode = new PrintWriter(outMsgWonNode, true);
        this.certificateBob = certificateBob;
    }

    public ReputationBotBob(InputStream incMsgWonNode, OutputStream outMsgWonNode, Certificate certificateBob, boolean standalone) {
        this.bobKeyPair = ECUtils.generateKeyPair();
        this.incMsgWonNode = new BufferedReader(new InputStreamReader(incMsgWonNode));
        this.outMsgWonNode = new PrintWriter(outMsgWonNode, true);
        this.certificateBob = certificateBob;
        this.standalone = false;
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
                    LOG.info("we get random send_randomhash from alice");
                    // Alice has sent the random send_randomhash
                    this.randomHashFromAlice = parts[1];
                    exchangeRandomHash(parts[1]);
                    break;
                case "[2]":
                    // no need to decode the blinded RT to bytes
                    this.blindedReputationTokenFromAlice = parts[1];
                    this.encodedReputationTokenFromAlice = parts[2];
                    this.reputationTokenFromAlice = MessageUtils.decodeRT(parts[2]);
                    LOG.info("Bob got the reputation token");
                    this.getBlindSignature();
                    this.exchangeRepuationToken();
                    this.rateTheTransaction();
                case "bye":
                    this.tearDown();
            }

            LOG.info("We wait for a message");
        }
    }

    private void tearDown() {
//        try {
//            this.aliceSocket.close();
//            this.bobSocket.close();
//        } catch (IOException e) {
//            e.printStackTrace();
//        }
    }

    @Override
    public void exchangeRandomHash(String randomHashFromAlice) {
        this.randomHashFromAlice = randomHashFromAlice;

        this.randomHashBobOriginal = null;
        try {
            randomHashBobOriginal = HashUtils.generateRandomHash();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        this.outMsgAlice.println("[1] " + randomHashBobOriginal);
    }

    @Override
    public void getBlindSignature() {
        // alice is already done and she is waiting for our token

        byte[] signedHashAlice = this.signHash();

        this.originalTokenForAlice = new Reputationtoken(certificateBob, signedHashAlice);
        try {
            this.blindedTokenForAlice = blindTokenForAlice(originalTokenForAlice);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private byte[] signHash() {
        byte[] signedHashBob = null;

        if(!standalone) {
            this.outMsgWonNode.println("[2] " + this.randomHashFromAlice);
            try {
                return MessageUtils.decodeToBytes(this.incMsgWonNode.readLine().split(" ")[1]);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        try {
            signedHashBob = RSAUtils.signString(this.bobKeyPair.getPrivate(), this.randomHashFromAlice);
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            e.printStackTrace();
        }
        return signedHashBob;
    }

    private String blindTokenForAlice(Reputationtoken tokenForAlice) throws IOException, InterruptedException {
        // We connect to the Reputationservice for blinding our token for alice
        LOG.info("we connect to reputation service and blind the token");

        WrappedSocket spSocket = new WrappedSocket("localhost", reputationServicePort, true);
        spSocket.writeOut("blind " + MessageUtils.toString(tokenForAlice));
        String blinded = spSocket.readIn();
        spSocket.writeOut("bye");
        spSocket.close();
        Thread.sleep(500);

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
        boolean validToken = false;
        try {
            validToken = this.verifyAliceToken();
        } catch (Exception e) {
            LOG.error("Some exceptions appeared: " + e);
            validToken = false; // just to be sure
        }

        // Atlast we write alice that everything is fine
        if(validToken) {
            this.outMsgAlice.println("everything is ok");
            this.outMsgWonNode.println("everything is ok");
        } else {
            this.outMsgAlice.println("invalid Token");
        }

        this.outMsgAlice.println("bye");
    }

    private boolean verifyAliceToken() throws IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        PublicKey alicePublicKey = this.reputationTokenFromAlice.getPubkeyFromCert();
        boolean validSignatureOfRandomHash = RSAUtils.verifySignature(
                this.reputationTokenFromAlice.getSignatureOfHash(),
                this.randomHashBobOriginal,
                alicePublicKey);

        if(!validSignatureOfRandomHash) {
            throw new SignatureException("Signature is invalid of the random element");
        }

        WrappedSocket spSocket = new WrappedSocket("localhost", reputationServicePort, true);
        spSocket.writeOut("verify " + this.blindedReputationTokenFromAlice + " " + this.encodedReputationTokenFromAlice);
        boolean verifyAnswer = spSocket.readIn().equals("valid");
        spSocket.writeOut("bye");
        spSocket.close();
        return verifyAnswer;
    }
}
