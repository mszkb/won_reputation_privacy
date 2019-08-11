package msz.bakk.cmd;

import msz.bakk.protocol.Message.Certificate;
import msz.bakk.protocol.Message.Message;
import msz.bakk.protocol.Message.Reputationtoken;
import msz.bakk.protocol.Reputation.Reputation;
import msz.bakk.protocol.Utils.BlindSignatureUtils;
import msz.bakk.protocol.Signer.Signer;
import msz.bakk.protocol.Utils.ECUtils;
import msz.bakk.protocol.Utils.MessageUtils;
import msz.bakk.protocol.Utils.RSAUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.jena.rdf.model.Model;
import org.apache.jena.riot.Lang;
import org.apache.jena.riot.RDFDataMgr;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.springframework.shell.standard.ShellComponent;
import org.springframework.shell.standard.ShellMethod;
import won.protocol.message.WonMessage;

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
    private BlindSignatureUtils blindSignature = new BlindSignatureUtils();

    private String myRandomHash = "";
    private byte[] signedHash;
    private Signer serviceProvider;

    private Certificate myCertificate;
    private Reputationtoken myReputationToken;
    private byte[] myBlindedToken;
    private String myUnblindSignedToken;
    private String myRandom;

    private String otherHash;
    private Reputationtoken otherReputationToken;
    private byte[] otherUnblindedToken;

    private AsymmetricKeyParameter publicKeySP;
    private AsymmetricKeyParameter spPublicKey;

    private HashMap<String, String> usedTokens;
    private HashMap<Integer, List<Reputation>> ratingStore;

    public CLI() {
        if(CmdApplication.shellprefix.equals("SP")) {
            try {
                this.initsp();
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            }

            LOG.info("-----------------------------------------------------------------------");
            LOG.info("You are " + CmdApplication.shellprefix);
            LOG.info("These are the commands to communicate with other users");
            LOG.info("-----------------------------------------------------------------------");
            LOG.info("blindsigntoken <token>");
            LOG.info("rate <rating> <comment> <token other user> <blindtoken other user> <original_hash>");
            LOG.info("-----------------------------------------------------------------------");
        } else {
            // To create your own certificate:
            // - remove this.myCertificate = new Certificate...
            // - type on Alice/Bob side:
            //     publickey
            //     Copy the public key
            //
            // - type on SP side:
            //     generatecertificate <public key>
            //     Copy that cert
            //
            // - type on Alice/Bob side:
            //      addcertificate <cert>

            // IDs are hardcoded as Program argument for simplification
            int userId = CmdApplication.shellprefix.equals("Alice") == true ? 1 : 1;
            userId = CmdApplication.shellprefix.equals("Bob") == true ? 2 : userId;
            userId = CmdApplication.shellprefix.equals("Carol") == true ? 3 : userId;
            userId = CmdApplication.shellprefix.equals("Charlie") == true ? 4 : userId;
            this.myCertificate = new Certificate(this.keyPair.getPublic(), userId);

            LOG.info("-----------------------------------------------------------------------");
            LOG.info("You are " + CmdApplication.shellprefix);
            LOG.info("These are the commands to rate another User");
            LOG.info("-----------------------------------------------------------------------");
            LOG.info("send_randomhash");
            LOG.info("receive_hash <hash from other user>");
            LOG.info("send_token_sp");
            LOG.info("receive_blindtoken_sp <blindtoken>");
            LOG.info("send_token_user <token> <blindtoken>");
            LOG.info("receive_token_user <token other user> <blindtoken other user>");
            LOG.info("rate_user <rating> <comment> <token other user> <blindtoken other user>");
            LOG.info("-----------------------------------------------------------------------");
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
        this.serviceProvider = new Signer();
        this.publicKeySP = this.serviceProvider.getPublicSignatureKey();

        LOG.info("Initilize Blind Signature RSA Utils and Rating store");
        LOG.info("This takes a little bit");
        this.ratingStore = new HashMap<>();
        this.usedTokens = new HashMap<>();
    }

    public void addPublicKeySP(AsymmetricKeyParameter spPubKey) {
        this.spPublicKey = spPubKey;
        this.blindSignature = new BlindSignatureUtils((RSAKeyParameters) spPubKey);
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

    // Helper
    public String getEncodedReputationToken() {
        try {
            return MessageUtils.toString(this.myReputationToken);
        } catch (IOException e) {
            e.printStackTrace();
        }

        return "";
    }

    public Reputationtoken getMyReputationToken() { return this.myReputationToken; }

    public String getMyRandomHash() {
        return this.myRandomHash;
    }

    public String getMyRandom() {
        return this.myRandom;
    }

    public String getMyUnblindSignedToken() {
        return this.myUnblindSignedToken;
    }

    public byte[] getMyBlindedToken () { return this.myBlindedToken; }

    @ShellMethod(value = "Shows the public key of current instance")
    public String publickey() throws IOException {
        return MessageUtils.toString(this.keyPair.getPublic());
    }

    public AsymmetricKeyParameter publicSignatureKey() {
        return this.publicKeySP;
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
    public WonMessage blindsigntoken(String encodedBlindedToken) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        if(!this.sp) {
            LOG.error("Only SP is allowed to use this method");
            return null;
        }

        String blindSignature = blindsigntoken_helper(encodedBlindedToken);
        WonMessage msg = RDFMessages.createWonMessage(RDFMessages.blindSignedAnswer(encodedBlindedToken, blindSignature));
        RDFDataMgr.write(System.out, msg.getMessageContent(), Lang.TRIG);

        LOG.info("We created the blind signature of your reputation token");
        LOG.info("Copy the the encoded String into the client side to rate the person");
        LOG.info(blindSignature);

        return msg;
    }

    /**
     * Helper method
     * for tests - it is also used by the proper method
     */
    public String blindsigntoken_helper(byte[] encodedBlindedToken) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        return MessageUtils.encodeBytes(this.serviceProvider.signBlindMessage(encodedBlindedToken));
    }

    public String blindsigntoken_helper(String encodedBlindedToken) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        return this.blindsigntoken_helper(MessageUtils.decodeToBytes(encodedBlindedToken));
    }

    /**
     * Helper method
     * for tests - to quickly check blind token and original token
     */
    public boolean verify(String blindedToken, String encodedToken) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        if(!this.sp) {
            LOG.error("Only SP is allowed");
            return false;
        }
        LOG.info("Verify blinded token with original token");
        Reputationtoken reputationtoken = MessageUtils.decodeRT(encodedToken);
        return this.blindSignature.verify(MessageUtils.decodeToBytes(blindedToken), reputationtoken.getBytes(), this.publicKeySP);
    }

    @ShellMethod(value = "rates user")
    public boolean rate(float rating, String message, String encodedToken, String encodedUnblindToken, String original) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        if(!this.sp) {
            LOG.error("Only SP is allowed");
            return false;
        }

        if(this.usedTokens.get(encodedUnblindToken) != null) {
            LOG.error("Token already used");
            return false;
        }

        Reputationtoken reputationtoken = MessageUtils.decodeRT(encodedToken);
        byte[] unblindedToken = MessageUtils.decodeToBytes(encodedUnblindToken);

        if(!this.blindSignature.verify(unblindedToken, reputationtoken.getBytes(), this.publicKeySP)) {
            LOG.error("BLIND TOKEN VERIFICATION FAILED");
            return false;
        }

        if(!RSAUtils.verifySignature(reputationtoken.getSignatureOfHash(), Utils.generateHash(original), reputationtoken.getPubkeyFromCert())) {
            LOG.error("HASH VERIFICATION FAILED");
            return false;
        }

        // User to rate
        int userId = reputationtoken.getCertificate().getID();

        if (this.ratingStore.containsKey(userId)) {
            List<Reputation> list = this.ratingStore.get(userId);
            list.add(new Reputation(rating, message, MessageUtils.decodeToBytes(encodedUnblindToken), MessageUtils.decodeRT(encodedToken)));
        } else {
            List<Reputation> newList = new ArrayList<>();
            newList.add(new Reputation(rating, message, MessageUtils.decodeToBytes(encodedUnblindToken), MessageUtils.decodeRT(encodedToken)));
            this.ratingStore.put(userId, newList);
        }

        usedTokens.put(encodedUnblindToken, original);

        LOG.info("OK");
        return true;
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

    @ShellMethod(value = "Generate a random send_randomhash and outputs a complete WoN RDF Message")
    public WonMessage send_randomhash() {
        if(this.sp) {
            LOG.error("SP is not allowed to execute this function");
            return null;
        }

        try {
            this.myRandom = Utils.generateRandomNumber();
            this.myRandomHash = Utils.generateHash(this.myRandom);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        Model m = RDFMessages.generateRandomHash(this.myRandomHash);
        WonMessage msg = RDFMessages.createWonMessage(m);
        RDFDataMgr.write(System.out, msg.getMessageContent(), Lang.TRIG);

        LOG.info("COPY next line into 'receive_hash <hash>' other users CLI Tool");
        LOG.info(this.myRandomHash);

        return msg;
    }

    // Helper methods do not create a WoN Message
    // Those methods are primarly used to save variables
    @ShellMethod(value = "HELPER - receive hash from other person, sign and save it")
    public void receive_hash(String hash) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, IOException, NoSuchProviderException {
        if(this.sp) {
            LOG.error("SP is not allowed to execute this function");
            return;
        }

        if(this.myRandomHash != null && this.myRandomHash.equals(hash)) {
            LOG.error("Oh - this is my own send_randomhash :)");
            LOG.error("Send this send_randomhash to your partner!");
            return;
        }

        // User provide random send_randomhash
        // sign the send_randomhash
        // store the signed send_randomhash
        // create reputation token

        LOG.info("Recieving send_randomhash from other user");
        LOG.info("Signing the send_randomhash from other user");
        this.otherHash = hash;
        this.signedHash = RSAUtils.signString(this.keyPair, hash);
        LOG.info("Creating Reputationtoken");


        if(this.myCertificate == null) {
            LOG.error("We do not have a certificate yet");
            LOG.info("Grab a certificate from the SP by sending him our public key");
            LOG.info("SP: generatecertificate <publickey>");
            LOG.info("WE: addcertificate <encodeded certificate>");
        }

        this.myReputationToken = new Reputationtoken(this.myCertificate, this.signedHash);
    }

    // Helper methods do not create a WoN Message
    // Those methods are primarly used to save variables
    @ShellMethod(value = "HELPER - we verify the hash")
    public boolean verify_hash() throws IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        if(this.signedHash == null) {
            LOG.info("No Hash recieved yet");
            LOG.info("Generate hash on other user and do 'receive_hash <HASH>' here");
        }

        return RSAUtils.verifySignature(this.signedHash, this.otherHash, this.myCertificate.getPublicKey());
    }

    @ShellMethod(value = "Send reputation token to the SP, SP returns the blinded token along with the original one")
    public WonMessage send_token_sp() throws NoSuchProviderException, NoSuchAlgorithmException, IOException {
        if(this.sp) {
            LOG.error("SP is not allowed to execute this function");
            return null;
        }

        if(this.signedHash == null) {
            LOG.info("No Hash recieved yet");
            LOG.info("Generate hash on other user and do 'receive_hash <HASH>' here");
        }

        this.myBlindedToken = this.blindSignature.blindMessage(this.myReputationToken.getBytes());

        Model m = RDFMessages.createBlindedReputationToken(MessageUtils.encodeBytes(this.myBlindedToken));

        WonMessage msg = RDFMessages.createWonMessage(m);
        RDFDataMgr.write(System.out, msg.getMessageContent(), Lang.TRIG);

        LOG.info("COPY next line into 'blindsigntoken <token>' other SP CLI Tool");
        LOG.info(MessageUtils.toString(this.myReputationToken));

        return msg;
    }

    // Helper methods do not create a WoN Message
    // Those methods are primarly used to save variables
    @ShellMethod(value = "HELPER - Recieve token from SP and store it")
    public void receive_blindtoken_sp(String blindSignedToken) {
        if(this.sp) {
            LOG.error("SP is not allowed to execute this function");
            return;
        }

        this.myUnblindSignedToken = MessageUtils.encodeBytes(this.unblind_helper(blindSignedToken));
    }

    @ShellMethod(value = "We exchange the reputation token - so the other is authorized to rate us")
    public WonMessage send_token_user() throws IOException {
        // Create message to exchange the token
        if(this.sp) {
            LOG.error("SP is not allowed to execute this function");
            return null;
        }

        Model m = RDFMessages.createExchangeTokenMessage(this.myReputationToken, this.myUnblindSignedToken);
        WonMessage msg = RDFMessages.createWonMessage(m);

        RDFDataMgr.write(System.out, msg.getMessageContent(), Lang.TRIG);

        LOG.info("This is the message to exchange the reputation token");
        LOG.info("It contains the token and the blind signature");


        LOG.info("COPY next two lines into 'receive_token_user <reputation token> <blindtoken>' other SP CLI Tool");
        LOG.info("Reputationtoken:");
        LOG.info(MessageUtils.toString(this.myReputationToken));
        LOG.info("Blinded reputation token:");
        LOG.info(this.myBlindedToken);

        return msg;
    }

    public byte[] unblind_helper(byte[] blindedToken) {
        return this.blindSignature.unblind(blindedToken);
    }

    public byte[] unblind_helper(String blindedToken) {
        return this.unblind_helper(MessageUtils.decodeToBytes(blindedToken));
    }

    // Helper methods do not create a WoN Message
    // Those methods are primarly used to save variables
    @ShellMethod(value = "HELPER - receive the reputation token and blinded token from the other user")
    public boolean receive_token_user(String unblindedToken, String encodededToken) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        if(this.sp) {
            LOG.error("SP is not allowed to execute this function");
            return false;
        }

        this.otherReputationToken = MessageUtils.decodeRT(encodededToken);
        this.otherUnblindedToken = MessageUtils.decodeToBytes(unblindedToken);

        boolean valid = this.verify_blindtoken_helper(this.otherUnblindedToken, this.otherReputationToken);
        if(!valid) {
            LOG.error("Blind Signature is not valid");
            return false;
        }
        boolean valid2 = verify_signature_helper(this.otherReputationToken.getSignatureOfHash(), this.myRandomHash, this.otherReputationToken.getPubkeyFromCert());
        if(!valid2) {
            LOG.error("Signature of hash is not valid");
            return false;
        }

        return true;
    }

    public boolean verify_blindtoken_helper(byte[] unblindedSignatureRT, Reputationtoken RT) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        return this.blindSignature.verify(unblindedSignatureRT, RT.getBytes(), this.spPublicKey);
    }

    public boolean verify_signature_helper(byte[] signature, String original, PublicKey publicKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        return RSAUtils.verifySignature(signature, original, publicKey);
    }

    public Reputationtoken getOtherReputationToken() {
        return this.otherReputationToken;
    }

    public String getOtherUnblindedToken() {
        return MessageUtils.encodeBytes(this.otherUnblindedToken);
    }

    @ShellMethod(value = "Check blind signature of the token (SP)")
    public WonMessage rate_user(float rating, String message) throws IOException {
        if(this.sp) {
            LOG.error("only SP is allowed to execute this function");
            return null;
        }

        // The message to rate a user contains:
        // - rating
        // - comment
        // - reputationtoken
        // - blindedtoken
        // - original random number (to verify the signature of the random hash)
        WonMessage rateMsg = RDFMessages.createWonMessage(
                RDFMessages.rate(rating, message, this.otherReputationToken, MessageUtils.encodeBytes(this.otherUnblindedToken), this.myRandom));

        RDFDataMgr.write(System.out, rateMsg.getMessageContent(), Lang.TRIG);

        LOG.info("COPY next 5 lines into 'receive_token_user <reputation token> <blindtoken>' other SP CLI Tool");
        LOG.info("Rating");
        LOG.info(rating);
        LOG.info("Comment");
        LOG.info(message);
        LOG.info("Reputationtoken:");
        LOG.info(MessageUtils.toString(this.otherReputationToken));
        LOG.info("Blinded reputation token:");
        LOG.info(MessageUtils.encodeBytes(this.otherUnblindedToken));
        LOG.info("Original random Number");
        LOG.info(this.myRandom);

        return rateMsg;
    }


}
