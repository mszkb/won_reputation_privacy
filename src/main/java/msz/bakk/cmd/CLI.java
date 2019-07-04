package msz.bakk.cmd;

import msz.bakk.protocol.Message.Certificate;
import msz.bakk.protocol.Message.Reputationtoken;
import msz.bakk.protocol.Reputation.Reputation;
import msz.bakk.protocol.Signer.BlindSignature;
import msz.bakk.protocol.Signer.Signer;
import msz.bakk.protocol.TrustedParty.Params;
import msz.bakk.protocol.TrustedParty.TrustedParty;
import msz.bakk.protocol.Utils.ECUtils;
import msz.bakk.protocol.Utils.MessageUtils;
import msz.bakk.protocol.Utils.RSAUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.jena.query.Dataset;
import org.apache.jena.riot.Lang;
import org.apache.jena.riot.RDFDataMgr;
import org.springframework.shell.standard.ShellComponent;
import org.springframework.shell.standard.ShellMethod;
import won.protocol.message.WonMessage;
import won.protocol.util.RdfUtils;

import java.io.IOException;
import java.security.*;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

@ShellComponent
public class CLI {

    private static final Log LOG = LogFactory.getLog(CLI.class);

    private boolean sp = false;

    private KeyPair keyPair = ECUtils.generateKeyPair();
    private String myRandomHash;
    private byte[] signedHash;
    private Params params;
    private BlindSignature blindSigner;
    private Signer serviceProvider;
    private Certificate myCertificate;
    private Reputationtoken myReputationToken;
    private WonMessage reputationTokenMSG;
    private WonMessage blindAnswer;
    private WonMessage rateMsg;

    private HashMap<String, String> usedTokens;
    private HashMap<Integer, List<Reputation>> ratingStore;

    public CLI() {
        if(CmdApplication.shellprefix.equals("SP")) {
            try {
                this.initsp();
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            }
        }
    }

    @ShellMethod(value = "Test method")
    public String test() {
        return "Hi, I'm a test";
    }

    ///-----------------------------------------------------------
    // ---------------------------------- STARTUP ----------------
    ///-----------------------------------------------------------

    @ShellMethod(value = "This Shell simulates the sp")
    public void initsp() throws NoSuchAlgorithmException {
        LOG.info("Initialize service provider");
        this.sp = true;

        LOG.info("Generate Parameters");
        this.params = new TrustedParty().generateParams();

        LOG.info("Use Parameters for Signer");
        this.serviceProvider = new Signer(this.params);

        LOG.info("Initilize Bling Signature RSA Utils and Rating store");
        this.blindSigner = new BlindSignature();
        this.ratingStore = new HashMap<>();
        this.usedTokens = new HashMap<>();
    }

    @ShellMethod(value = "Generating certificate for the users")
    public String generatecertificate(String encodedPubKey) throws NoSuchProviderException, NoSuchAlgorithmException, IOException {
        PublicKey publicKey = MessageUtils.decodePubKey(encodedPubKey);

        if(this.serviceProvider == null) {
            LOG.error("initsp was not invoked - you want to generate a certificate");
            LOG.info("we execute initsp for you :)");
            this.initsp();
        }

        Certificate cert = this.serviceProvider.registerClient(publicKey);

        String encodedCert = MessageUtils.toString(cert);

        return encodedCert;
    }

    @ShellMethod(value = "Shows the public key of current instance")
    public String publickey() throws IOException {
        return MessageUtils.toString(this.keyPair.getPublic());
    }

    @ShellMethod(value = "Returns user id")
    public String userid() {
        LOG.info(this.myCertificate.getID());
        return String.valueOf(this.myCertificate.getID());
    }

    @ShellMethod(value = "Set the certificate for us")
    public void addcertificate(String encodedcertificate) {
        if(this.sp) {
            LOG.error("SP is not allowed");
            return;
        }

        this.myCertificate = MessageUtils.decodeCert(encodedcertificate);
    }


    ///----------------------------------------------------------------
    // ---------------------------------- PROTOCOL SP ---------------
    ///----------------------------------------------------------------

    @ShellMethod(value = "Blind and sign given token")
    public String blindsigntoken(String encodedToken) {
        if(!this.sp) {
            LOG.error("Only SP is allowed");
            return encodedToken;
        }

        Reputationtoken reputationtoken = MessageUtils.decodeRT(encodedToken);
        String blindSignature = MessageUtils.encodeBytes(this.blindSigner.blindAndSign(reputationtoken.getBytes()));

        WonMessage msg = RDFMessages.blindAnswer(reputationtoken, blindSignature);
        RDFDataMgr.write(System.out, msg.getCompleteDataset(), Lang.TRIG);

        LOG.info("We created the blind signature of your reputation token");
        LOG.info("Copy the the encoded String into the client side to rate the person");
        LOG.info(blindSignature);
        return blindSignature;
    }

    public String verify(String blindedToken, String encodedToken) {
        if(!this.sp) {
            LOG.error("Only SP is allowed");
            return "";
        }

        Reputationtoken reputationtoken = MessageUtils.decodeRT(encodedToken);
        boolean verify = this.blindSigner.verify(MessageUtils.decodeToBytes(blindedToken), reputationtoken.getBytes());

        if(verify) {
            return "Blinded token valid";
        } else {
            return "Blinded token invalid";
        }
    }

    @ShellMethod(value = "rates user")
    public String rate(float rating, String message, String encodedToken, String encodedBlindToken, String originalhash) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        if(!this.sp) {
            LOG.error("Only SP is allowed");
            return "FAILED";
        }

        if(this.usedTokens.get(encodedBlindToken) != null) {
            LOG.error("Token already used");
            return "FAILED - Token already used";
        }

        Reputationtoken reputationtoken = MessageUtils.decodeRT(encodedToken);
        byte[] blindedToken = MessageUtils.decodeToBytes(encodedBlindToken);

        if(!this.blindSigner.verify(blindedToken, reputationtoken)) {
            LOG.error("BLIND TOKEN VERIFICATION FAILED");
            return "FAILED - blindedtoken verification failed";
        }

        if(!RSAUtils.verifySignature(reputationtoken.getSignatureOfHash(), originalhash, reputationtoken.getPubkeyFromCert())) {
            LOG.error("HASH VERIFICATION FAILED");
            return "FAILED - hash signature verification failed";
        }

        // User to rate
        int userId = reputationtoken.getCertificate().getID();

        if (this.ratingStore.containsKey(userId)) {
            List<Reputation> list = this.ratingStore.get(userId);
            list.add(new Reputation(rating, message, MessageUtils.decodeToBytes(encodedBlindToken), MessageUtils.decodeRT(encodedToken)));
        } else {
            List<Reputation> newList = new ArrayList<>();
            newList.add(new Reputation(rating, message, MessageUtils.decodeToBytes(encodedBlindToken), MessageUtils.decodeRT(encodedToken)));
            this.ratingStore.put(userId, newList);
        }

        usedTokens.put(encodedBlindToken, originalhash);

        LOG.info("OK");
        return "OK";
    }

    @ShellMethod(value = "Shows the AVG rating of given user id")
    public String showrating(String userid) {
        if(!this.sp) {
            LOG.error("Only SP is allowed");
            return "FAILED";
        }

        float avg = 0;

        if(this.ratingStore.get(Integer.valueOf(userid)) != null) {
            List<Reputation> userRep = this.ratingStore.get(Integer.valueOf(userid));
            avg = 0;
            for (Reputation reputation : userRep) {
                avg += reputation.getRating();
            }

            avg = avg / userRep.size();
        }

        LOG.info("AVG rating: " + avg);

        return String.valueOf(avg);
    }

    @ShellMethod(value = "Prints out all the rating of given user id")
    public String showallratings(String userid) {
        if(!this.sp) {
            LOG.error("Only SP is allowed");
            return "FAILED";
        }

        List<Reputation> reputations = this.ratingStore.get(Integer.parseInt(userid));
        return reputations.toString();
    }

    ///----------------------------------------------------------------
    // ---------------------------------- PROTOCOL USER ---------------
    ///----------------------------------------------------------------

    @ShellMethod(value = "Generate a random hash and outputs a complete WoN RDF Message")
    public String genrandomhash() {
        if(this.sp) {
            LOG.error("SP is not allowed to execute this function");
            return null;
        }

        WonMessage msg = RDFMessages.generateRandomHash();
        Dataset content = msg.getMessageContent();
        String datasetString = RdfUtils.writeDatasetToString(content, Lang.TRIG);
        RDFDataMgr.write(System.out, msg.getCompleteDataset(), Lang.TRIG);

        String[] split = datasetString.split("\n");     // ugly spliting
        this.myRandomHash = split[2].trim().split("\"")[1];   // Random Hash        System.out.println("\nGenerated random hash - exchange this with the other person");
        LOG.info("\nThis is your hash - exchange this with your Atom partner");
        LOG.info("Other: exchangehash " + this.myRandomHash);
        return this.myRandomHash;
    }

    @ShellMethod(value = "Send random Hash to the other person - there is no return message")
    public void exchangehash(String hash) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, IOException, NoSuchProviderException {
        if(this.sp) {
            LOG.error("SP is not allowed to execute this function");
            return;
        }

        if(this.myRandomHash != null && this.myRandomHash.equals(hash)) {
            LOG.error("Oh - this is my own hash :)");
            LOG.error("Send this hash to your partner!");
            return;
        }

        // User provide random hash
        // sign the hash
        // store the signed hash
        // create reputation token

        LOG.info("Recieving hash from other user");
        LOG.info("Signing the hash from other user");
        this.signedHash = RSAUtils.signString(this.keyPair, hash);
        LOG.info("Creating Reputationtoken");

        if(this.myCertificate == null) {
            LOG.error("We do not have a certificate yet");
            LOG.info("Grab a certificate from the SP by sending him our public key");
            LOG.info("SP: generatecertificate <publickey>");
            LOG.info("WE: addcertificate <encodeded certificate>");
        }
    }

    @ShellMethod(value = "verifies given original hash with the signed one")
    public boolean verifyhashsignature(String originalHash) throws IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        return RSAUtils.verifySignature(this.signedHash, originalHash, this.myCertificate.getPublicKey());
    }

    @ShellMethod(value = "Send reputation token to the SP, SP returns the blinded token along with the original one")
    public String blindreputationtokenmsg() throws NoSuchProviderException, NoSuchAlgorithmException, IOException {
        if(this.sp) {
            LOG.error("SP is not allowed to execute this function");
            return "";
        }

        this.myReputationToken = new Reputationtoken(this.myCertificate, this.signedHash);
        this.reputationTokenMSG = RDFMessages.createReputationToken(MessageUtils.encodeBytes(this.signedHash), this.myCertificate);
        RDFDataMgr.write(System.out, this.reputationTokenMSG.getCompleteDataset(), Lang.TRIG);

        LOG.info("We want to blind sign our reputation token");
        LOG.info("We print out a base64 encoded reputation token");
        LOG.info("Next step: Send token to SP .. blindandsign <myReputationToken>");
        return MessageUtils.toString(this.myReputationToken);
    }

    @ShellMethod(value = "We exchange the reputation token - so the other is authorized to rate us")
    public String[] createexchangetokenmsg(String blindedToken) throws IOException {
        // Create message to exchange the token
        if(this.sp) {
            LOG.error("SP is not allowed to execute this function");
        }

        this.blindAnswer = RDFMessages.blindAnswer(this.myReputationToken, blindedToken);
        RDFDataMgr.write(System.out, this.blindAnswer.getCompleteDataset(), Lang.TRIG);

        LOG.info("This is the message to exchange the reputation token");
        LOG.info("It contains the token and the blind signature");

        String[] tokens = {MessageUtils.toString(this.myReputationToken), blindedToken};
        return tokens;
    }

    @ShellMethod(value = "Check blind signature of the token (SP)")
    public void rateuser(float rating, String message, String encodedReputationToken, String blindedReputationToken) {
        if(this.sp) {
            LOG.error("only SP is allowed to execute this function");
            return;
        }

        Reputationtoken reputationtoken = MessageUtils.decodeRT(encodedReputationToken);

        // The message to rate a user contains:
        // - rating
        // - comment
        // - reputationtoken
        // - blindedtoken
        // - original hash (to verify the signature of the random)
        this.rateMsg = RDFMessages.rate(rating, message, reputationtoken, blindedReputationToken, this.myRandomHash);

        RDFDataMgr.write(System.out, this.rateMsg.getCompleteDataset(), Lang.TRIG);

        LOG.info("This a message which recieves the SP");
    }
}
