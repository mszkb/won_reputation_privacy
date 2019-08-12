package msz.bakk.cmd;

import msz.bakk.protocol.Message.Message;
import msz.bakk.protocol.Utils.ECUtils;
import msz.bakk.protocol.Utils.MessageUtils;
import msz.bakk.protocol.vocabulary.REP;
import org.apache.activemq.command.MessageAck;
import org.apache.jena.query.Dataset;
import org.apache.jena.rdf.model.*;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.junit.Before;
import org.junit.Test;
import won.protocol.message.WonMessage;
import won.protocol.util.RdfUtils;

import java.io.IOException;
import java.security.*;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.assertFalse;
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

    private CLI cliSP;

    @Before
    public void setUp() throws IOException, NoSuchProviderException, NoSuchAlgorithmException, ClassNotFoundException {

        // We initialize our system by:
        // - create CLI instance for each actor (alice, bob, SP)
        // - SP must be initilized, because of Signer parameters
        // - SP creates certificates for alice and bob

        cliAlice = new CLI();
        cliBob = new CLI();

        cliSP = new CLI();
        cliSP.initsp();
        cliAlice.addcertificate(cliSP.generatecertificate(cliAlice.publickey()));
        cliBob.addcertificate(cliSP.generatecertificate(cliBob.publickey()));

        AsymmetricKeyParameter spPubKey = cliSP.publicSignatureKey();

        cliAlice.addPublicKeySP(spPubKey);
        cliBob.addPublicKeySP(spPubKey);
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
     * This test represents the message to the SP
     * - send_randomhash
     * - receive_hash
     * - send_token_sp
     *
     * We test here if the reputation token contains all the right information
     * to verify the signed hash with the public key inside the certificate
     */
    @Test
    public void test_cli_protocol() throws NoSuchProviderException, IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {

        // After registration User generates a hash out of a random number
        cliAlice.send_randomhash();
        cliBob.send_randomhash();

        // Send hash to other user
        cliAlice.receive_hash(cliBob.getMyRandomHash());
        cliBob.receive_hash(cliAlice.getMyRandomHash());

        // User creates a reputation token, blinds the token and sends to the SP
        cliAlice.send_token_sp();
        cliBob.send_token_sp();

        // SP sends back a blind signed token
        cliAlice.receive_blindtoken_sp(cliSP.blindsigntoken_helper(MessageUtils.encodeBytes(cliAlice.getMyBlindedToken())));
        cliBob.receive_blindtoken_sp(cliSP.blindsigntoken_helper(cliBob.getMyBlindedToken()));

        // Both user unblinds the token and exchange it along with the reputation token
        cliAlice.send_token_user();
        cliBob.send_token_user();

        // Both user checks the unblinded token with the original one with the publickey of the SP
        assertTrue(cliAlice.receive_token_user(cliBob.getMyUnblindSignedToken(), cliBob.getEncodedReputationToken()));
        assertTrue(cliBob.receive_token_user(cliAlice.getMyUnblindSignedToken(), cliAlice.getEncodedReputationToken()));

        // Checks are positiv. Users can rate each other
        cliAlice.rate_user(5.0f, "Smooth transaction");
        cliBob.rate_user(4.5f, "Smooth transaction 2");

        // User send to the SP
        // rating, comment/message, unblinded signed token, reputation token, original random number
        assertTrue(cliSP.rate(5.0f, "Smooth transaction", MessageUtils.toString(cliAlice.getOtherReputationToken()), cliAlice.getOtherUnblindedToken(), cliAlice.getMyRandom()));
        assertTrue(cliSP.rate(4.5f, "Smooth transaction 2", MessageUtils.toString(cliBob.getOtherReputationToken()), cliBob.getOtherUnblindedToken(), cliBob.getMyRandom()));

        // We check if SP persists the rating
        assertThat(cliSP.showrating("1")).contains("4.5");
        assertThat(cliSP.showrating("2")).contains("5.0");
    }

    @Test
    public void test_use_own_token() throws NoSuchAlgorithmException, NoSuchProviderException, IOException, SignatureException, InvalidKeyException {
        cliAlice.send_randomhash();
        cliBob.send_randomhash();
        cliAlice.receive_hash(cliBob.getMyRandomHash());
        cliAlice.send_token_sp();

        cliAlice.receive_blindtoken_sp(cliSP.blindsigntoken_helper(cliAlice.getMyBlindedToken()));

        // We cant use our token on ourself, because we do not know the original random number
        // This will be detected by the SP and might result in a penality
        assertFalse(cliSP.rate(5.0f, "Smooth transaction", MessageUtils.toString(cliAlice.getMyReputationToken()), cliAlice.getMyUnblindSignedToken(), cliAlice.getMyRandom()));
    }


    /**
     * This test represents 'send_randomhash'
     * and verifies against a regex pattern
     */
    @Test
    public void test_won_message_randomHash() {
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
    public void test_won_message_verify_hash() throws NoSuchProviderException, IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
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

        // the receive_hash method signs the hash with own private key
        // and stores the original hash into 'otherHash' field
        cliAlice.receive_hash(hashBob);
        cliBob.receive_hash(hashAlice);

        // We test if the hash we signed was signed correctly
        // Verify the signature with the public key
        assertTrue(cliAlice.verify_hash());
        assertTrue(cliBob.verify_hash());
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
     * - exchange_token
     *
     * We send the blinded reputation token to the SP and the SP returns a blind signature
     * We unblind the blind signature, and send the unblinded signature and reputation token to the other user
     * Other user receives unblinded signature and the reputation token and verifies them
     */
    @Test
    public void test_won_message_sendtokensp() throws NoSuchProviderException, IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        // We use helper methods to get out the randomhash
        // for the full test @see test_won_message_randomHash
        cliAlice.send_randomhash();
        cliBob.send_randomhash();
        cliAlice.receive_hash(cliBob.getMyRandomHash());
        cliBob.receive_hash(cliAlice.getMyRandomHash());


        // CLI Tool creates WonMessage
        // send_token_sp returns a WonMessage containing the blinded token which is sent to the SP
        // we extract REP.BLINDED_REPUTATIONTOKEN and pass it to the SP
        WonMessage msgBlindedTokenAlice = cliAlice.send_token_sp();
        Model modelBlindTokenAlice = msgBlindedTokenAlice.getMessageContent().getUnionModel();
        Statement stmtBlindTokenAlice = modelBlindTokenAlice.getProperty(RdfUtils.getBaseResource(modelBlindTokenAlice), REP.BLINDED_REPUTATIONTOKEN);
        String blindTokenAliceForSP = stmtBlindTokenAlice.getObject().asLiteral().getLexicalForm();

        // The Service Provider receives the blinded token from alice
        // SP blind signs the token and we sends back a WonMessage
        // The WonMessage contains the blinded token and the blind signed token
        WonMessage msgSPblindTokenForAlice = cliSP.blindsigntoken(blindTokenAliceForSP);
        Model modelBlindTokenForAlice = msgSPblindTokenForAlice.getMessageContent().getUnionModel();
        Statement stmtBlindTokenForAlice = modelBlindTokenForAlice.getProperty(RdfUtils.getBaseResource(modelBlindTokenForAlice), REP.BLIND_SIGNED_REPUTATIONTOKEN);
        String blindTokenForAlice = stmtBlindTokenForAlice.getObject().asLiteral().getLexicalForm();

        // alice recieves the token by setting the token into a field
        // receive_blindtoken_sp unblinds the blind signature
        cliAlice.receive_blindtoken_sp(blindTokenForAlice);

        // SP can verify the unblinded token with the encoded original token
        assertTrue(cliSP.verify(cliAlice.getMyUnblindSignedToken(), cliAlice.getEncodedReputationToken()));
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
        // We use some helper methods to make tests easier
        // for detailed tests: @see test_won_message_sendtokensp
        //                          test_won_message_verify_hash
        //                          test_won_message_randomHash
        cliAlice.send_randomhash();
        cliBob.send_randomhash();
        // @see test_won_message_verify_hash
        cliAlice.receive_hash(cliBob.getMyRandomHash());
        cliBob.receive_hash(cliAlice.getMyRandomHash());
        cliAlice.send_token_sp();
        cliBob.send_token_sp();
        // @see test_won_message_sendtokensp
        String blindedTokenAliceForBob = cliSP.blindsigntoken_helper(cliAlice.getMyBlindedToken());
        String blindedTokenBobForAlice = cliSP.blindsigntoken_helper(cliBob.getMyBlindedToken());
        cliAlice.receive_blindtoken_sp(blindedTokenAliceForBob);
        cliBob.receive_blindtoken_sp(blindedTokenBobForAlice);
        cliAlice.receive_token_user(cliBob.getMyUnblindSignedToken(), cliBob.getEncodedReputationToken());
        cliBob.receive_token_user(cliAlice.getMyUnblindSignedToken(), cliAlice.getEncodedReputationToken());


        // We want to test the WonMessage of rating a user
        // Those messages contains:
        // - rating
        // - comment
        // - reputation token
        // - unblinded signed reputation token
        // - original random number

        // We extract all of these out of the message
        WonMessage msgAliceRatesBob = cliAlice.rate_user(5.0f, "Nice and smooth transaction");
        Model modelAliceRatesBob = msgAliceRatesBob.getMessageContent().getUnionModel();
        Statement stmtAliceRatesBobRating = modelAliceRatesBob.getProperty(RdfUtils.getBaseResource(modelAliceRatesBob), REP.RATING);
        Statement stmtAliceRatesBobMessage = modelAliceRatesBob.getProperty(RdfUtils.getBaseResource(modelAliceRatesBob), REP.RATING_COMMENT);
        Statement stmtAliceRatesBobAliceOriginal = modelAliceRatesBob.getProperty(RdfUtils.getBaseResource(modelAliceRatesBob), REP.ORIGINAL);
        Statement stmtAliceRatesBobBlindSignedToken = modelAliceRatesBob.getProperty(RdfUtils.getBaseResource(modelAliceRatesBob), REP.BLIND_SIGNED_REPUTATIONTOKEN);
        Statement stmtAliceRatesBobReputationToken = modelAliceRatesBob.getProperty(RdfUtils.getBaseResource(modelAliceRatesBob), REP.REPUTATIONTOKEN_ENCODED);
        String aliceRatesBobRating = stmtAliceRatesBobRating.getObject().asLiteral().getLexicalForm();
        String aliceRatesBobComment = stmtAliceRatesBobMessage.getObject().asLiteral().getLexicalForm();
        String aliceRatesBobReputationToken = stmtAliceRatesBobReputationToken.getObject().asLiteral().getLexicalForm();
        String aliceRatesBobBlindedToken = stmtAliceRatesBobBlindSignedToken.getObject().asLiteral().getLexicalForm();
        String aliceRatesBobOriginal = stmtAliceRatesBobAliceOriginal.getObject().asLiteral().getLexicalForm();


        WonMessage msgBobRatesAlice = cliBob.rate_user(4.5f, "2 Nice and smooth transaction");
        Model modelBobRatesAlice = msgBobRatesAlice.getMessageContent().getUnionModel();
        Statement stmtBobRatesAliceRating = modelBobRatesAlice.getProperty(RdfUtils.getBaseResource(modelBobRatesAlice), REP.RATING);
        Statement stmtBobRatesAliceMessage = modelBobRatesAlice.getProperty(RdfUtils.getBaseResource(modelBobRatesAlice), REP.RATING_COMMENT);
        Statement stmtBobRatesAliceOriginal = modelBobRatesAlice.getProperty(RdfUtils.getBaseResource(modelBobRatesAlice), REP.ORIGINAL);
        Statement stmtBobRatesAliceBlindSignedToken = modelBobRatesAlice.getProperty(RdfUtils.getBaseResource(modelBobRatesAlice), REP.BLIND_SIGNED_REPUTATIONTOKEN);
        Statement stmtBobRatesAliceReputationToken = modelBobRatesAlice.getProperty(RdfUtils.getBaseResource(modelBobRatesAlice), REP.REPUTATIONTOKEN_ENCODED);
        String bobRatesAliceRating = stmtBobRatesAliceRating.getObject().asLiteral().getLexicalForm();
        String bobRatesAliceComment = stmtBobRatesAliceMessage.getObject().asLiteral().getLexicalForm();
        String bobRatesAliceReputationToken = stmtBobRatesAliceReputationToken.getObject().asLiteral().getLexicalForm();
        String bobRatesAliceBlindedToken = stmtBobRatesAliceBlindSignedToken.getObject().asLiteral().getLexicalForm();
        String bobRatesAliceOriginal = stmtBobRatesAliceOriginal.getObject().asLiteral().getLexicalForm();

        cliSP.rate(
                Float.parseFloat(aliceRatesBobRating),
                aliceRatesBobComment,
                aliceRatesBobReputationToken,
                aliceRatesBobBlindedToken,
                aliceRatesBobOriginal);

        cliSP.rate(
                Float.parseFloat(bobRatesAliceRating),
                bobRatesAliceComment,
                bobRatesAliceReputationToken,
                bobRatesAliceBlindedToken,
                bobRatesAliceOriginal);

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

        String blindedTokenAliceForBob = cliSP.blindsigntoken_helper(cliAlice.getMyBlindedToken());
        String blindedTokenBobForAlice = cliSP.blindsigntoken_helper(cliBob.getMyBlindedToken());

        cliAlice.receive_blindtoken_sp(blindedTokenAliceForBob);
        cliBob.receive_blindtoken_sp(blindedTokenBobForAlice);

        cliAlice.receive_token_user(cliBob.getMyUnblindSignedToken(), cliBob.getEncodedReputationToken());
        cliBob.receive_token_user(cliAlice.getMyUnblindSignedToken(), cliAlice.getEncodedReputationToken());

        cliSP.rate(
                5.0f,
                "Nice and smooth transaction",
                MessageUtils.toString(cliAlice.getOtherReputationToken()),
                cliAlice.getOtherUnblindedToken(),
                cliAlice.getMyRandom());

        cliSP.rate(
                4.5f,
                "Nice and quick",
                MessageUtils.toString(cliBob.getOtherReputationToken()),
                cliBob.getOtherUnblindedToken(),
                cliBob.getMyRandom());

        assertFalse(cliSP.rate(
                4.0f,
                "I rated Bob twice",
                MessageUtils.toString(cliAlice.getOtherReputationToken()),
                cliAlice.getOtherUnblindedToken(),
                cliAlice.getMyRandom()));

        assertThat(cliSP.showrating("2")).isEqualTo("5.0");
    }


}
