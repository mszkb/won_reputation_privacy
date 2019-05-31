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
        } catch (IOException | InvalidAlgorithmParameterException | NoSuchProviderException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        this.certificateAlice = certificateAlice;
    }

    public ReputationBotAlice(InputStream incMsgWonNode, OutputStream outMsgWonNode, Certificate certificateAlice) {
        try {
            this.aliceKeyPair = ECUtils.generateKeyPair();
        } catch (InvalidAlgorithmParameterException | NoSuchProviderException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        this.incMsgWonNode = new BufferedReader(new InputStreamReader(incMsgWonNode));
        this.outMsgWonNode = new PrintWriter(outMsgWonNode);

        this.incMsgBob = this.incMsgWonNode;
        this.outMsgBob = this.outMsgWonNode;

        this.certificateAlice = certificateAlice;
        this.standalone = true;
    }

    private void connectToBob() throws IOException {
        this.bobSocket = new Socket("localhost", this.bobPort);
        this.incMsgBob = new BufferedReader(new InputStreamReader((this.bobSocket).getInputStream()));
        this.outMsgBob = new PrintWriter(((Socket) this.bobSocket).getOutputStream());

        this.incMsgBob.readLine(); // We wait until bob is ready
    }


    @Override
    public void run() {
        try {
            if(!standalone) {
                this.connectToBob();            // connect to bob
            }
            this.exchangeRandomHash();      // immediatlty send random hash to bob
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
                    // open another socket to the SP with token, original hash, message and rating
                    this.blindedTokenForBob = parts[1];
                    this.encodedReputationTokenFromBob = parts[2];
                    this.originalReputationTokenFromBob = MessageUtils.decodeRT(parts[2]);
                    this.rateTheTransaction();

                    break;
            }
        }
    }

    @Override
    public void getBlindSignature() {
        byte[] signedHashBob = null;
        try {
            signedHashBob = RSAUtils.signString(this.aliceKeyPair.getPrivate(), this.randomHashFromBob);
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            e.printStackTrace();
        }
        this.originalTokenForBob = new Reputationtoken(certificateAlice, signedHashBob);
        try {
            this.blindedTokenForBob = blindTokenForBob(originalTokenForBob);
            Thread.sleep(2000);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private String blindTokenForBob(Reputationtoken tokenForBob) throws IOException {
        // We connect to the Reputationservice for blinding our token for bob

        WrappedSocket spSocket = new WrappedSocket("localhost", reputationServicePort, true);
        spSocket.writeOut("blind " + MessageUtils.toString(tokenForBob));
        String blinded = spSocket.readIn();
        spSocket.writeOut("bye");
        spSocket.close();

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
            LOG.error("Could not create random hash: " + e.getMessage());
        }

        this.outMsgBob.println("[1] " + this.randomHashAliceOriginal);
    }

    @Override
    public void exchangeRepuationToken() {
        try {
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
        } else {
            this.outMsgBob.println("invalid Token");
        }
    }

    private boolean verifyBobToken() throws IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        PublicKey alicePublicKey = this.originalReputationTokenFromBob.getPubkeyFromCert();
        boolean validSignatureOfRandomHash = RSAUtils.verifySignature(
                this.originalReputationTokenFromBob.getSignatureOfHash(),
                this.randomHashAliceOriginal,
                alicePublicKey);

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
