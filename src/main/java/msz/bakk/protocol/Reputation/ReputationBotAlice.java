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
 * This is the sending Bot, in WoN this is the Requestor
 * <p>
 * Alice begins
 * <p>
 * Alice connects to Bob
 * Alice sends the random Hash to Bob
 * Alice waits until Bob sends his random Hash
 * Alice signs the send_randomhash and sends it with her cert to the RepuationServer
 * Alice waits until the ReputationServer sends a blind signature to her
 * Alice connects to Bob again
 * Alice sends the blind signature to Bob
 * Alice waits until she recieves the ReputationToken from Bob
 * Alice sends Bobs ReputationToken with rating and the message to the ReputationServer
 */
public class ReputationBotAlice implements IRepuationBot {

    private static final Log LOG = LogFactory.getLog(ReputationBotAlice.class);

    private final int reputationServicePort = 5555;

    private final int bobPort = 5055;
    private boolean standalone = false;
    private KeyPair aliceKeyPair = null;
    private Certificate certificateAlice;

    private ServerSocket aliceSocket;
    private Socket bobSocket;
    private BufferedReader incMsgBob;
    private PrintWriter outMsgBob;

    private BufferedReader incMsgWonNode;
    private PrintWriter outMsgWonNode;

    private String randomHashAliceOriginal = null;

    private String randomHashFromBob = null;
    private String blindedReputationTokenFromBob;
    private Reputationtoken originalReputationTokenFromBob;
    private String encodedReputationTokenFromBob;

    private Reputationtoken originalTokenForBob;
    private String blindedTokenForBob;

    public ReputationBotAlice(Socket socket, Certificate certificateAlice) {
        try {
            this.aliceKeyPair = ECUtils.generateKeyPair();
            this.incMsgWonNode = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            this.outMsgWonNode = new PrintWriter(socket.getOutputStream());
        } catch (IOException e) {
            e.printStackTrace();
        }

        this.certificateAlice = certificateAlice;
    }

    public ReputationBotAlice(InputStream incMsgWonNode, OutputStream outMsgWonNode, Certificate certificateAlice) throws NoSuchProviderException {
        this.aliceKeyPair = ECUtils.generateKeyPair();
        this.incMsgWonNode = new BufferedReader(new InputStreamReader(incMsgWonNode));
        this.outMsgWonNode = new PrintWriter(outMsgWonNode, true);

        this.incMsgBob = this.incMsgWonNode;
        this.outMsgBob = this.outMsgWonNode;

        this.certificateAlice = certificateAlice;
        this.standalone = true;
    }

    public ReputationBotAlice(InputStream incMsgWonNode, OutputStream outMsgWonNode, Certificate certificateAlice, boolean standalone) throws NoSuchProviderException {
        this.aliceKeyPair = ECUtils.generateKeyPair();
        this.incMsgWonNode = new BufferedReader(new InputStreamReader(incMsgWonNode));
        this.outMsgWonNode = new PrintWriter(outMsgWonNode, true);

        this.certificateAlice = certificateAlice;
        this.standalone = false;
    }

    private void connectToBob() throws IOException {
        LOG.info("We connect to Bob");
        this.bobSocket = new Socket("localhost", this.bobPort);
        this.incMsgBob = new BufferedReader(new InputStreamReader((this.bobSocket).getInputStream()));
        this.outMsgBob = new PrintWriter((this.bobSocket).getOutputStream(), true);

        this.incMsgBob.readLine(); // We wait until bob is ready
    }


    @Override
    public void run() {
        try {
            if(!standalone) {
                this.connectToBob();            // connect to bob
            }
            this.exchangeRandomHash();      // immediatlty send random send_randomhash to bob
            this.commandDispatch();         // wait for bob and continue protocol
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void commandDispatch() throws IOException {
        String inputLine;

        LOG.info("We wait for a message");
        while ((inputLine = this.incMsgBob.readLine()) != null) {
            LOG.info("Bob wrote something: " + inputLine);
            String[] parts = inputLine.split(" ");

            switch (parts[0]) {
                case "[1]":
                    this.randomHashFromBob = parts[1];
                    this.getBlindSignature();   // we send cert and signed Hash to SP
                                                // wait for the answer (another socket)
                                                // then create a reputation token
                                                // and send it to Bob
                    this.exchangeRepuationToken();
                                                // loop is over and we wait for bob
                    break;
                case "[2]":
                    // bob answered with his  reputationtoken
                    // now we are obligated to rate the transaction
                    // open another socket to the SP with token, original send_randomhash, message and rating
                    this.blindedReputationTokenFromBob = parts[1];
                    this.encodedReputationTokenFromBob = parts[2];
                    this.originalReputationTokenFromBob = MessageUtils.decodeRT(parts[2]);
                    this.rateTheTransaction();
                    break;
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
    public void getBlindSignature() {
        byte[] signedHashBob = this.signHash();

        this.originalTokenForBob = new Reputationtoken(certificateAlice, signedHashBob);
        try {
            LOG.info("we blind the token for bob");
            this.blindedTokenForBob = blindTokenForBob(originalTokenForBob);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private byte[] signHash() {
        byte[] signedHashBob = null;

        if(!standalone) {
            LOG.info("Contact client: We need to sign the random send_randomhash");
            this.outMsgWonNode.println("[1] " + this.randomHashFromBob);
            try {
                return MessageUtils.decodeToBytes(this.incMsgWonNode.readLine().split(" ")[1]);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        try {
            signedHashBob = RSAUtils.signString(this.aliceKeyPair.getPrivate(), this.randomHashFromBob);
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            e.printStackTrace();
        }
        return signedHashBob;
    }

    private String blindTokenForBob(Reputationtoken tokenForBob) throws IOException, InterruptedException {
        // We connect to the Reputationservice for blinding our token for bob

        LOG.info("we connect to reputation service and blind the token");
        WrappedSocket spSocket = new WrappedSocket("localhost", reputationServicePort, true);
        spSocket.writeOut("blind " + MessageUtils.toString(tokenForBob));
        String blinded = spSocket.readIn();
        spSocket.writeOut("bye");
        spSocket.close();
        Thread.sleep(500);

        LOG.info("token is blinded");
        return blinded;
    }

    @Override
    public void exchangeRandomHash(String randomHash) {
        // In case the client also sends the randomHash
    }

    public void exchangeRandomHash() {
        try {
            this.randomHashAliceOriginal = HashUtils.generateRandomHash();
        } catch (NoSuchAlgorithmException e) {
            LOG.error("Could not create random send_randomhash: " + e.getMessage());
        }

        LOG.info("sending send_randomhash to bob");
        this.outMsgBob.println("[1] " + this.randomHashAliceOriginal);
    }

    @Override
    public void exchangeRepuationToken() {
        try {
            LOG.info("We send the blinded token and the encoded original token to bob");
            this.outMsgBob.println("[2] " + this.blindedTokenForBob + " " + MessageUtils.toString(this.originalTokenForBob));
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @Override
    public void rateTheTransaction() {
        boolean validToken = false;
        try {
            validToken = this.verifyBobToken();
        } catch (Exception e) {
            LOG.error("Some exceptions appeared: " + e);
            validToken = false; // just to be sure
        }

        // Atlast we write bob that everything is fine
        if(validToken) {
            this.outMsgBob.println("everything is ok");
            this.outMsgWonNode.println("everything is ok");
        } else {
            this.outMsgBob.println("invalid Token");
        }

        this.outMsgBob.println("bye");
    }

    private boolean verifyBobToken() throws IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        PublicKey bobPublicKey = this.originalReputationTokenFromBob.getPubkeyFromCert();
        boolean validSignatureOfRandomHash = RSAUtils.verifySignature(
                this.originalReputationTokenFromBob.getSignatureOfHash(),
                this.randomHashAliceOriginal,
                bobPublicKey);

        if(!validSignatureOfRandomHash) {
            throw new SignatureException("Signature is invalid of the random element");
        }

        WrappedSocket spSocket = new WrappedSocket("localhost", reputationServicePort, true);
        spSocket.writeOut("verify " + this.blindedReputationTokenFromBob + " " + this.encodedReputationTokenFromBob);
        boolean verifyAnswer = spSocket.readIn().equals("valid");
        spSocket.writeOut("bye");
        spSocket.close();
        return verifyAnswer;
    }
}
