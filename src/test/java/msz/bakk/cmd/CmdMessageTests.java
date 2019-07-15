package msz.bakk.cmd;

import msz.bakk.protocol.Utils.ECUtils;
import msz.bakk.protocol.Utils.MessageUtils;
import msz.bakk.protocol.Utils.RSAUtils;
import msz.bakk.protocol.vocabulary.REP;
import org.apache.jena.query.Dataset;
import org.apache.jena.rdf.model.*;
import org.junit.Before;
import org.junit.Test;
import won.protocol.message.WonMessage;
import won.protocol.util.RdfUtils;

import java.io.IOException;
import java.security.*;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.assertTrue;

/**
 * Those tests are designed as followed:
 * - Most of the methods return a WonMessage
 * - The tests check the WonMessage
 * - The tool itself accepts only simple Strings
 *
 * The get the simple Strings we need to encode certain Objects in base64
 */
public class CmdMessageTests {
    private String regexHash = "^[a-zA-Z0-9]+$";
    private KeyPair keyPair = ECUtils.generateKeyPair();

    private CLI cliAlice;
    private CLI cliBob;
    private CLI cliCarol;
    private CLI cliCharlie;

    private CLI cliSP;

    @Before
    public void setUp() throws IOException, NoSuchProviderException, NoSuchAlgorithmException {

        // We initialize our system by:
        // - create CLI instance for each actor (alice, bob, SP)
        // - SP must be initilized, because of Signer parameters
        // - SP creates certificates for alice and bob

        cliAlice = new CLI();
        cliBob = new CLI();
        cliCarol = new CLI();
        cliCharlie = new CLI();

        cliSP = new CLI();

        cliSP.initsp();
        cliAlice.addcertificate(cliSP.generatecertificate(cliAlice.publickey()));
        cliBob.addcertificate(cliSP.generatecertificate(cliBob.publickey()));
        cliCarol.addcertificate(cliSP.generatecertificate(cliCarol.publickey()));
        cliCharlie.addcertificate(cliSP.generatecertificate(cliCharlie.publickey()));
    }

    @Test
    public void test_won_message_manual() {
        Model model = RDFMessages.generateRandomHash();
        WonMessage msg = RDFMessages.createWonMessage(model);

        Dataset content = msg.getMessageContent();
        RDFNode aliceTokenNode = RdfUtils.findFirstPropertyFromResource(content, RdfUtils.getBaseResource(model), REP.RANDOM_HASH);

        if (aliceTokenNode.isLiteral()) {
            System.out.println(aliceTokenNode.asLiteral().getString());
        }
    }

    /**
     * This test represents 'send_randomhash'
     * and verifies against a regex pattern
     */
    @Test
    public void test_randomHash() {
        // We create a WonMessage randomHash
        WonMessage msgAliceHash = cliAlice.send_randomhash();

        // We get the model out of the WonMessage
        Model modelAliceHash = msgAliceHash.getMessageContent().getUnionModel();

        // We want to get the Property inside the base resource (BASE_URI - https://w3id.org/won/ext/reputation#)
        Statement stmtAlice = modelAliceHash.getProperty(RdfUtils.getBaseResource(modelAliceHash), REP.RANDOM_HASH);
        assertThat(stmtAlice).isNotNull();

        // We test the hash against a regex pattern
        // getObject asLiteral getLexicalForm allows us to get the value
        String hashAlice  = stmtAlice.getObject().asLiteral().getLexicalForm();
        assertTrue(hashAlice.matches(regexHash));


        WonMessage msgBobHash = cliBob.send_randomhash();
        Model modelBobHash = msgBobHash.getMessageContent().getUnionModel();
        Statement stmtBob = modelBobHash.getProperty(RdfUtils.getBaseResource(modelBobHash), REP.RANDOM_HASH);
        assertThat(stmtBob).isNotNull();

        String hashBob  = stmtBob.getObject().asLiteral().getLexicalForm();
        assertTrue(hashBob.matches(regexHash));
    }

    /**
     *  This test represents
     *  - send_randomhash
     *  - receive_hash <hash>
     *  - verify_hash
     *
     *  receive hash saves the hash from Bob into a field
     *  in addition Alice signs the hash from bob
     *
     *  verify_hash checks if the hash and the signature are valid against the public key inside the certificate
     */
    @Test
    public void test_verify_hash() throws NoSuchProviderException, IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        WonMessage msgAliceHash = cliAlice.send_randomhash();
        Model modelAliceHash = msgAliceHash.getMessageContent().getUnionModel();
        Statement stmtAlice = modelAliceHash.getProperty(RdfUtils.getBaseResource(modelAliceHash), REP.RANDOM_HASH);
        assertThat(stmtAlice).isNotNull();

        String hashAlice  = stmtAlice.getObject().asLiteral().getLexicalForm();
        assertTrue(hashAlice.matches(regexHash));


        WonMessage msgBobHash = cliBob.send_randomhash();
        Model modelBobHash = msgBobHash.getMessageContent().getUnionModel();
        Statement stmtBob = modelBobHash.getProperty(RdfUtils.getBaseResource(modelBobHash), REP.RANDOM_HASH);
        assertThat(stmtBob).isNotNull();

        String hashBob  = stmtBob.getObject().asLiteral().getLexicalForm();
        assertTrue(hashBob.matches(regexHash));


        // To verify the hash we get the signed hash out of the
        // Receive_hash signs the hash with own private key and stores the original hash into 'otherHash'
        cliAlice.receive_hash(hashBob);
        cliBob.receive_hash(hashAlice);

        // Verifying the hash does not need any arguments
        // the sent hash and the signedhash are saved into fields
        assertTrue(cliAlice.verify_hash());
        assertTrue(cliBob.verify_hash());
    }

    /**
     * This test represents the message to the SP
     * - send_randomhash
     * - receive_hash
     * - send_token_sp
     *
     * We test here if the reputation token contains all the right information
     * to verify the signed hash with the public key inside the certificate
     */
    @Test
    public void test_send_token_sp() throws NoSuchProviderException, IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        WonMessage msgAliceHash = cliAlice.send_randomhash();
        Model modelAliceHash = msgAliceHash.getMessageContent().getUnionModel();
        Statement stmtAlice = modelAliceHash.getProperty(RdfUtils.getBaseResource(modelAliceHash), REP.RANDOM_HASH);
        assertThat(stmtAlice).isNotNull();

        String hashAlice  = stmtAlice.getObject().asLiteral().getLexicalForm();
        assertTrue(hashAlice.matches(regexHash));


        WonMessage msgBobHash = cliBob.send_randomhash();
        Model modelBobHash = msgBobHash.getMessageContent().getUnionModel();
        Statement stmtBob = modelBobHash.getProperty(RdfUtils.getBaseResource(modelBobHash), REP.RANDOM_HASH);
        assertThat(stmtBob).isNotNull();

        String hashBob  = stmtBob.getObject().asLiteral().getLexicalForm();
        assertTrue(hashBob.matches(regexHash));


        cliAlice.receive_hash(hashBob);
        cliBob.receive_hash(hashAlice);


        WonMessage msgAliceTokenMsg = cliAlice.send_token_sp();        // CLI Tool creates WonMessage
        Model msgAliceToken = msgAliceTokenMsg.getMessageContent().getUnionModel();    // We only want the message content

        // We traverse the graph
        // First we want the Reputation triple
        Statement stmtAliceToken = msgAliceToken.getProperty(RdfUtils.getBaseResource(msgAliceToken), REP.REPUTATIONTOKEN);

        // Next we want to check the signed random hash
        Statement stmtAliceSignedHash = stmtAliceToken.getProperty(REP.SIGNED_RANDOM_HASH);
        String aliceSignedHash = stmtAliceSignedHash.getObject().asLiteral().getLexicalForm();

        // We check the signature from alice with the original hash from bob with the public key of alice
        assertTrue(RSAUtils.verifySignature(
                MessageUtils.decodeToBytes(aliceSignedHash),
                hashBob,
                MessageUtils.decodePubKey(cliAlice.publickey())));



        WonMessage msgBobTokenMsg = cliBob.send_token_sp();
        Dataset content = msgBobTokenMsg.getMessageContent();
        Model msgBobToken = content.getUnionModel();
        Statement stmtBobToken = msgBobToken.getProperty(RdfUtils.getBaseResource(msgBobToken), REP.REPUTATIONTOKEN);
        Statement stmtBobSignedHash = stmtBobToken.getProperty(REP.SIGNED_RANDOM_HASH);
        String bobSignedHash = stmtBobSignedHash.getObject().asLiteral().getLexicalForm();

        assertTrue(RSAUtils.verifySignature(
                MessageUtils.decodeToBytes(bobSignedHash),
                hashAlice,
                MessageUtils.decodePubKey(cliBob.publickey())));
    }

    /**
     * This test represents the message the SP returns to the user
     *
     * Alice/Bob
     * - send_randomhash
     * - receive_hash
     * - send_token_sp
     *
     * SP
     * - blindsigntoken
     *
     * Alice/Bob
     * - receive_blindtoken
     *
     * We send the reputation token to the SP and the SP returns a blind signature
     * We get the blind signature out of the Message, then we use a helper method (cliSP.verify)
     * to get access to the verification method of the SP to verify the blind signature
     */
    @Test
    public void test_blindsigntoken() throws NoSuchProviderException, IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        cliAlice.send_randomhash();
        cliBob.send_randomhash();

        // We use helper methods to get out the randomhash
        // The WonMessage which contains the randomhash was tested before
        cliAlice.receive_hash(cliBob.getMyRandomHash());
        cliBob.receive_hash(cliAlice.getMyRandomHash());

        // CLI Tool creates WonMessage
        // send_token_sp saves the reputationtoken into a field for easier testing
        cliAlice.send_token_sp();
        cliBob.send_token_sp();

        // We use some helper methods to make tests easier
        String encodedTokenAlice = cliAlice.getEncodedReputationToken();
        String encodedTokenBob = cliBob.getEncodedReputationToken();


        // The Service Provider receives the base64 encoded token from alice
        // SP blind signs the token and we get a WonMessage
        // The WonMessage contains the original token and the blinded token
        WonMessage msgSPblindTokenForAlice = cliSP.blindsigntoken(encodedTokenAlice);
        Model modelBlindTokenForAlice = msgSPblindTokenForAlice.getMessageContent().getUnionModel();
        Statement stmtBlindTokenAlice = modelBlindTokenForAlice.getProperty(RdfUtils.getBaseResource(modelBlindTokenForAlice), REP.BLIND_SIGNED_REPUTATIONTOKEN);
        String blindTokenForAlice = stmtBlindTokenAlice.getObject().asLiteral().getLexicalForm();

        // alice recieves the token by setting the token into a field
        cliAlice.receive_blindtoken_sp(blindTokenForAlice);
        assertThat(cliAlice.getMyBlindedToken()).isNotNull();

        WonMessage msgSPblindTokenForBob = cliSP.blindsigntoken(encodedTokenBob);
        Model modelBlindTokenForBob = msgSPblindTokenForBob.getMessageContent().getUnionModel();
        Statement stmtBlindTokenBob = modelBlindTokenForBob.getProperty(RdfUtils.getBaseResource(modelBlindTokenForAlice), REP.BLIND_SIGNED_REPUTATIONTOKEN);
        String blindTokenForBob = stmtBlindTokenBob.getObject().asLiteral().getLexicalForm();
        cliBob.receive_blindtoken_sp(blindTokenForBob);

        assertThat(cliBob.getMyBlindedToken()).isNotNull();

        // SP can verify the blinded token with the base64 encoded original token
        assertTrue(cliSP.verify(blindTokenForAlice, encodedTokenAlice));
        assertTrue(cliSP.verify(blindTokenForBob, encodedTokenBob));
    }

    /**
     * This test represents the message the SP returns to the user
     *
     * Alice/Bob
     * - send_randomhash
     * - receive_hash
     * - send_token_sp
     *
     * SP
     * - blindsigntoken
     *
     * Alice/Bob
     * - receive_blindtoken_sp
     * - send_token_user
     * - rate_user
     *
     * SP
     * - rate
     */
    @Test
    public void test_rate_person() throws NoSuchProviderException, IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        cliAlice.send_randomhash();
        cliBob.send_randomhash();

        // We use helper methods to get out the randomhash
        // The WonMessage which contains the randomhash was tested before
        cliAlice.receive_hash(cliBob.getMyRandomHash());
        cliBob.receive_hash(cliAlice.getMyRandomHash());

        // CLI Tool creates WonMessage
        // send_token_sp saves the reputationtoken into a field for easier testing
        cliAlice.send_token_sp();
        cliBob.send_token_sp();

        // We use some helper methods to make tests easier
        String encodedTokenAliceforBob = cliAlice.getEncodedReputationToken();
        String encodedTokenBobforAlice = cliBob.getEncodedReputationToken();

        String blindedTokenAliceForBob = cliSP.blindsigntoken_helper(encodedTokenAliceforBob);
        String blindedTokenBobForAlice = cliSP.blindsigntoken_helper(encodedTokenBobforAlice);

        cliAlice.receive_blindtoken_sp(blindedTokenAliceForBob);
        cliBob.receive_blindtoken_sp(blindedTokenBobForAlice);

        cliAlice.receive_token_user(encodedTokenBobforAlice, blindedTokenBobForAlice);
        cliBob.receive_token_user(encodedTokenBobforAlice, blindedTokenAliceForBob);


        WonMessage msgAliceRatesBob = cliAlice.rate_user(5.0f, "Nice and smooth transaction");
        Model modelAliceRatesBob = msgAliceRatesBob.getMessageContent().getUnionModel();
        Statement stmtAliceRatesBobRating = modelAliceRatesBob.getProperty(RdfUtils.getBaseResource(modelAliceRatesBob), REP.RATING);
        Statement stmtAliceRatesBobMessage = modelAliceRatesBob.getProperty(RdfUtils.getBaseResource(modelAliceRatesBob), REP.RATING_COMMENT);
        String aliceRatesBobRating = stmtAliceRatesBobRating.getObject().asLiteral().getLexicalForm();
        String aliceRatesBobComment = stmtAliceRatesBobMessage.getObject().asLiteral().getLexicalForm();

        assertThat(aliceRatesBobRating).isEqualTo("5.0"); // We receive a string here
        assertThat(aliceRatesBobComment).isEqualTo("Nice and smooth transaction");


        WonMessage msgBobRatesAlice = cliAlice.rate_user(4.5f, "2 Nice and smooth transaction");
        Model modelBobRatesAlice = msgBobRatesAlice.getMessageContent().getUnionModel();
        Statement stmtBobRatesAliceRating = modelBobRatesAlice.getProperty(RdfUtils.getBaseResource(modelBobRatesAlice), REP.RATING);
        Statement stmtBobRatesAliceMessage = modelBobRatesAlice.getProperty(RdfUtils.getBaseResource(modelBobRatesAlice), REP.RATING_COMMENT);
        String bobRatesAliceRating = stmtBobRatesAliceRating.getObject().asLiteral().getLexicalForm();
        String bobRatesAliceComment = stmtBobRatesAliceMessage.getObject().asLiteral().getLexicalForm();

        assertThat(bobRatesAliceRating).isEqualTo("4.5"); // We receive a string here
        assertThat(bobRatesAliceComment).isEqualTo("2 Nice and smooth transaction");


        cliSP.rate(
                5.0f,
                aliceRatesBobComment,
                encodedTokenBobforAlice,
                blindedTokenBobForAlice,
                cliAlice.getMyRandomHash());

        cliSP.rate(
                4.5f,
                bobRatesAliceComment,
                encodedTokenAliceforBob,
                blindedTokenAliceForBob,
                cliBob.getMyRandomHash());

        assertThat(cliSP.showrating("1")).isEqualTo("4.5");
        assertThat(cliSP.showrating("2")).isEqualTo("5.0");


    }

    @Test
    public void test_use_token_twice() throws NoSuchAlgorithmException, NoSuchProviderException, IOException, SignatureException, InvalidKeyException {
        cliAlice.send_randomhash();
        cliBob.send_randomhash();

        // We use helper methods to get out the randomhash
        // The WonMessage which contains the randomhash was tested before
        cliAlice.receive_hash(cliBob.getMyRandomHash());
        cliBob.receive_hash(cliAlice.getMyRandomHash());

        // CLI Tool creates WonMessage
        // send_token_sp saves the reputationtoken into a field for easier testing
        cliAlice.send_token_sp();
        cliBob.send_token_sp();

        // We use some helper methods to make tests easier
        String encodedTokenAliceforBob = cliAlice.getEncodedReputationToken();
        String encodedTokenBobforAlice = cliBob.getEncodedReputationToken();

        String blindedTokenAliceForBob = cliSP.blindsigntoken_helper(encodedTokenAliceforBob);
        String blindedTokenBobForAlice = cliSP.blindsigntoken_helper(encodedTokenBobforAlice);

        cliAlice.receive_blindtoken_sp(blindedTokenAliceForBob);
        cliBob.receive_blindtoken_sp(blindedTokenBobForAlice);

        cliAlice.receive_token_user(encodedTokenBobforAlice, blindedTokenBobForAlice);
        cliBob.receive_token_user(encodedTokenBobforAlice, blindedTokenAliceForBob);

        cliSP.rate(
                5.0f,
                "Nice and smooth transaction",
                encodedTokenBobforAlice,
                blindedTokenBobForAlice,
                cliAlice.getMyRandomHash());

        cliSP.rate(
                4.5f,
                "Nice and quick",
                encodedTokenAliceforBob,
                blindedTokenAliceForBob,
                cliBob.getMyRandomHash());

        assertThat(cliSP.rate(
                4.0f,
                "I rated Bob twice",
                encodedTokenBobforAlice,
                blindedTokenBobForAlice,
                cliAlice.getMyRandomHash())).contains("FAILED");

        assertThat(cliSP.showrating("2")).isEqualTo("5.0");
    }

    @Test
    public void test_use_own_token() throws NoSuchAlgorithmException, NoSuchProviderException, IOException, SignatureException, InvalidKeyException {
        cliAlice.send_randomhash();
        cliBob.send_randomhash();

        // We use helper methods to get out the randomhash
        // The WonMessage which contains the randomhash was tested before
        cliAlice.receive_hash(cliBob.getMyRandomHash());
        cliBob.receive_hash(cliAlice.getMyRandomHash());

        // CLI Tool creates WonMessage
        // send_token_sp saves the reputationtoken into a field for easier testing
        cliAlice.send_token_sp();
        cliBob.send_token_sp();

        // We use some helper methods to make tests easier
        String encodedTokenAliceforBob = cliAlice.getEncodedReputationToken();
        String encodedTokenBobforAlice = cliBob.getEncodedReputationToken();

        String blindedTokenAliceForBob = cliSP.blindsigntoken_helper(encodedTokenAliceforBob);
        String blindedTokenBobForAlice = cliSP.blindsigntoken_helper(encodedTokenBobforAlice);

        cliAlice.receive_blindtoken_sp(blindedTokenAliceForBob);
        cliBob.receive_blindtoken_sp(blindedTokenBobForAlice);

        WonMessage msgAliceSendsBobTokens = cliAlice.send_token_user();
        Model modelAliceSendsBobTokens = msgAliceSendsBobTokens.getMessageContent().getUnionModel();
        Statement stmtAliceRatesBobRating1 = modelAliceSendsBobTokens.getProperty(RdfUtils.getBaseResource(modelAliceSendsBobTokens), REP.BLIND_SIGNED_REPUTATIONTOKEN);
        String aliceSendsBobTokensToken1 = stmtAliceRatesBobRating1.getObject().asLiteral().getLexicalForm();

        Statement stmtAliceToken = modelAliceSendsBobTokens.getProperty(RdfUtils.getBaseResource(modelAliceSendsBobTokens), REP.REPUTATIONTOKEN);
        Statement stmtAliceSignedHash = stmtAliceToken.getProperty(REP.SIGNED_RANDOM_HASH);
        String aliceSignedHash = stmtAliceSignedHash.getObject().asLiteral().getLexicalForm();

        assertThat(aliceSendsBobTokensToken1).isNotNull();
        assertThat(aliceSignedHash).isNotNull();

        cliAlice.receive_token_user(encodedTokenBobforAlice, blindedTokenBobForAlice);
        cliBob.receive_token_user(encodedTokenBobforAlice, blindedTokenAliceForBob);

        assertThat(cliSP.rate(
                5.0f,
                "Nice and smooth transaction",
                encodedTokenAliceforBob,
                blindedTokenAliceForBob,
                cliAlice.getMyRandomHash())).contains("FAILED");
    }
}
