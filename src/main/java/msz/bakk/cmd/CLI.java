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
    private String blindedToken;

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
            // TODO what is the User ID in WoN?
            this.myCertificate = new Certificate(this.keyPair.getPublic(), 1);

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

        LOG.info("Generate Parameters");
        this.params = new TrustedParty().generateParams();

        LOG.info("Use Parameters for Signer");
        this.serviceProvider = new Signer(this.params);

        LOG.info("Initilize Blind Signature RSA Utils and Rating store");
        LOG.info("This takes a little bit");
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
        RDFDataMgr.write(System.out, msg.getMessageContent(), Lang.TRIG);

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
            return "FAILED - send_randomhash signature verification failed";
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

    @ShellMethod(value = "Generate a random send_randomhash and outputs a complete WoN RDF Message")
    public String send_randomhash() {
        if(this.sp) {
            LOG.error("SP is not allowed to execute this function");
            return null;
        }

        WonMessage msg = RDFMessages.generateRandomHash();
        Dataset content = msg.getMessageContent();
        String datasetString = RdfUtils.writeDatasetToString(content, Lang.TRIG);
        RDFDataMgr.write(System.out, msg.getMessageContent(), Lang.TRIG);

        String[] split = datasetString.split("\n");     // ugly spliting
        this.myRandomHash = split[2].trim().split("\"")[1];   // Random Hash        System.out.println("\nGenerated random send_randomhash - exchange this with the other person");
        LOG.info("\nThis is your send_randomhash - exchange this with your Atom partner");
        LOG.info("COPY THIS - paste it into 'receive_hash <HASH>' at other User side");
        return this.myRandomHash;
    }

    @ShellMethod(value = "Send random Hash to the other person - there is no return message")
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
        this.signedHash = RSAUtils.signString(this.keyPair, hash);
        LOG.info("Creating Reputationtoken");


        if(this.myCertificate == null) {
            LOG.error("We do not have a certificate yet");
            LOG.info("Grab a certificate from the SP by sending him our public key");
            LOG.info("SP: generatecertificate <publickey>");
            LOG.info("WE: addcertificate <encodeded certificate>");
        }
    }

    @ShellMethod(value = "verifies given original send_randomhash with the signed one")
    public boolean verify_hash(String originalHash) throws IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        return RSAUtils.verifySignature(this.signedHash, originalHash, this.myCertificate.getPublicKey());
    }

    @ShellMethod(value = "Send reputation token to the SP, SP returns the blinded token along with the original one")
    public String send_token_sp() throws NoSuchProviderException, NoSuchAlgorithmException, IOException {
        if(this.sp) {
            LOG.error("SP is not allowed to execute this function");
            return "";
        }

        this.myReputationToken = new Reputationtoken(this.myCertificate, this.signedHash);
        this.reputationTokenMSG = RDFMessages.createReputationToken(MessageUtils.encodeBytes(this.signedHash), this.myCertificate);
        RDFDataMgr.write(System.out, this.reputationTokenMSG.getMessageContent(), Lang.TRIG);

        LOG.info("We want to blind sign our reputation token");
        LOG.info("We print out a base64 encoded reputation token");
        LOG.info("Next step: Send token to SP .. blindandsign <myReputationToken>");
        LOG.info("COPY THIS - into 'blindsigntoken <TOKEN>' at SP side");
        return MessageUtils.toString(this.myReputationToken);
    }

    @ShellMethod(value = "Recieve token from SP and store it")
    public void receive_blindtoken_sp(String blindedtoken) {
        if(this.sp) {
            LOG.error("SP is not allowed to execute this function");
            return;
        }

        this.blindedToken = blindedtoken;
    }

    @ShellMethod(value = "We exchange the reputation token - so the other is authorized to rate us")
    public String[] send_token_user() throws IOException {
        // Create message to exchange the token
        if(this.sp) {
            LOG.error("SP is not allowed to execute this function");
        }

        this.blindAnswer = RDFMessages.blindAnswer(this.myReputationToken, this.blindedToken);
        RDFDataMgr.write(System.out, this.blindAnswer.getMessageContent(), Lang.TRIG);

        LOG.info("This is the message to exchange the reputation token");
        LOG.info("It contains the token and the blind signature");

        String[] tokens = {MessageUtils.toString(this.myReputationToken), this.blindedToken};

        LOG.info("COPY THOSE 2 ... original and blinded token - into 'rate_user 5.0 aaa <token> <blindtoken>' at other Users");
        LOG.info(MessageUtils.toString(this.myReputationToken));
        LOG.info(this.blindedToken);

        return tokens;
    }

    @ShellMethod(value = "Check blind signature of the token (SP)")
    public void rate_user(float rating, String message, String encodedReputationToken, String blindedReputationToken) {
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
        // - original send_randomhash (to verify the signature of the random)
        LOG.info("COPY THOSE 5 ... - into 'rate 5.0 aaa <token> <blindtoken> <original hash>' at SP");
        LOG.info(5.0f);
        LOG.info("ABC MESSAGE");
        LOG.info(encodedReputationToken);
        LOG.info(this.blindedToken);
        LOG.info(this.myRandomHash);
        this.rateMsg = RDFMessages.rate(rating, message, reputationtoken, blindedReputationToken, this.myRandomHash);

        RDFDataMgr.write(System.out, this.rateMsg.getMessageContent(), Lang.TRIG);

        LOG.info("This a message which recieves the SP");
    }
}
