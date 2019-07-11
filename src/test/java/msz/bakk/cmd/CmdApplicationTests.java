package msz.bakk.cmd;

import msz.bakk.protocol.Utils.ECUtils;
import org.apache.jena.query.Dataset;
import org.apache.jena.riot.Lang;
import org.junit.Before;
import org.junit.Test;
import won.protocol.message.WonMessage;
import won.protocol.util.RdfUtils;

import java.io.IOException;
import java.security.*;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.assertTrue;

public class CmdApplicationTests {

    private String testHash = "^[a-zA-Z0-9]+$";
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
    public void test_random_hash_message() {
        WonMessage msg = RDFMessages.generateRandomHash();
        Dataset content = msg.getMessageContent();

        String datasetString = RdfUtils.writeDatasetToString(content, Lang.TRIG);

        String[] split = datasetString.split("\n");     // ugly spliting
        String hash = split[2].trim().split("\"")[1];   // Random Hash

        System.out.println(hash);

        assertTrue(hash.matches(testHash));
    }

    @Test
    public void test_sign_random_hash() throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
//        String randomHash = Utils.generateRandomHash();
//        byte[] signedHash = RSAUtils.signString(keyPair, randomHash);
//        String signedHashString = MessageUtils.encodeBytes(signedHash);

//        WonMessage reputationToken = RDFMessages.createReputationToken(signedHashString, this.);
//        Dataset content = reputationToken.getMessageContent();
//        String datasetString = RdfUtils.writeDatasetToString(content, Lang.TRIG);
//
//        String signedHashOfMessage = datasetString.split("\n")[9].trim().split("\"")[1];
//
//        System.out.println(signedHashOfMessage);
//
//        assertThat(signedHashOfMessage).isNotNull();
    }

    @Test
    public void test_genrandom() {
        //
        // We test a simple random send_randomhash generation
        // To test it we match it with a regex
        //

        assertThat(cliBob.send_randomhash().matches(testHash));
        assertThat(cliAlice.send_randomhash().matches(testHash));
    }

    @Test
    public void test_exchangehash() throws NoSuchProviderException, IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        //
        // In the exchange process each actor creates a reputation token
        // Inside the reputation token there is the public key of the user
        // So to verify the signature we take that public key and check
        // it along with the original send_randomhash and the signature
        //

        String randomHashBob = cliBob.send_randomhash();
        cliAlice.receive_hash(randomHashBob);
        assertTrue(cliAlice.verify_hash(randomHashBob));

        String randomHashAlice = cliAlice.send_randomhash();
        cliBob.receive_hash(randomHashAlice);
        assertTrue(cliBob.verify_hash(randomHashAlice));
    }

    @Test
    public void test_blindReputationtoken() throws NoSuchProviderException, IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        //
        // We create a random send_randomhash - exchange it - create a reputation token
        // then we send it to the SP to blind sign it
        //

        String randomHashAlice = cliAlice.send_randomhash();
        String randomHashBob = cliBob.send_randomhash();

        cliAlice.receive_hash(randomHashBob);
        cliBob.receive_hash(randomHashAlice);

        assertTrue(cliAlice.verify_hash(randomHashBob));
        assertTrue(cliBob.verify_hash(randomHashAlice));

        String encodedTokenAlice = cliAlice.send_token_sp();
        String encodedTokenBob = cliBob.send_token_sp();

        String blindedTokenAlice = cliSP.blindsigntoken(encodedTokenAlice);
        String blindedTokenBob = cliSP.blindsigntoken(encodedTokenBob);

        assertThat(cliSP.verify(blindedTokenAlice, encodedTokenAlice)).isEqualTo("Blinded token valid");
        assertThat(cliSP.verify(blindedTokenBob, encodedTokenBob)).isEqualTo("Blinded token valid");
    }

    @Test
    public void test_exchangeToken() throws NoSuchProviderException, IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        String randomHashAlice = cliAlice.send_randomhash();
        String randomHashBob = cliBob.send_randomhash();

        cliAlice.receive_hash(randomHashBob);
        cliBob.receive_hash(randomHashAlice);

        assertTrue(cliAlice.verify_hash(randomHashBob));
        assertTrue(cliBob.verify_hash(randomHashAlice));

        String encodedTokenAlice = cliAlice.send_token_sp();
        String encodedTokenBob = cliBob.send_token_sp();

        String blindedTokenAlice = cliSP.blindsigntoken(encodedTokenAlice);
        String blindedTokenBob = cliSP.blindsigntoken(encodedTokenBob);

        cliAlice.receive_blindtoken_sp(blindedTokenAlice);
        cliBob.receive_blindtoken_sp(blindedTokenBob);

        String[] tokensAlice = cliAlice.send_token_user();
        String[] tokensBob = cliAlice.send_token_user();
    }

    @Test
    public void test_rate() throws NoSuchProviderException, IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        String randomHashAlice = cliAlice.send_randomhash();
        String randomHashBob = cliBob.send_randomhash();

        cliAlice.receive_hash(randomHashBob);   // alice recieves bob's random send_randomhash
        cliBob.receive_hash(randomHashAlice);   // bob recieves alice's random send_randomhash

        assertTrue(cliAlice.verify_hash(randomHashBob));
        assertTrue(cliBob.verify_hash(randomHashAlice));

        String encodedTokenAlice = cliAlice.send_token_sp();  // This is the message the SP gets to blind sign given token
        String encodedTokenBob = cliBob.send_token_sp();      // This is the message the SP gets to blind sign given token

        String blindedTokenAlice = cliSP.blindsigntoken(encodedTokenAlice); // SP returns blind signed token
        String blindedTokenBob = cliSP.blindsigntoken(encodedTokenBob);     // --"--

        cliAlice.receive_blindtoken_sp(blindedTokenAlice);
        cliBob.receive_blindtoken_sp(blindedTokenBob);

        String[] tokensAlice = cliAlice.send_token_user();  // Alice creates the message to exchange the reputation token to bob
        String[] tokensBob = cliBob.send_token_user();      // Bob -----"------ to alice

        // To rate Bob Alice uses the tokens from bob
        // to verify the signature, alice uses her send_randomhash
        this.cliAlice.rate_user(4.0f, "Smooth and fast transaction", tokensBob[0], tokensBob[1]);
        this.cliBob.rate_user(5.0f, "Everything fine", tokensAlice[0], tokensAlice[1]);

        assertThat(this.cliSP.rate(4.0f, "Smooth and fast transaction", tokensBob[0], tokensBob[1], randomHashAlice)).isEqualTo("OK");
        assertThat(this.cliSP.rate(5.0f, "Everything fine", tokensAlice[0], tokensAlice[1], randomHashBob)).isEqualTo("OK");
    }

    @Test
    public void test_checkRating() throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, IOException, NoSuchProviderException {
        String randomHashAlice = cliAlice.send_randomhash();
        String randomHashBob = cliBob.send_randomhash();

        cliAlice.receive_hash(randomHashBob);   // alice recieves bob's random send_randomhash
        cliBob.receive_hash(randomHashAlice);   // bob recieves alice's random send_randomhash

        assertTrue(cliAlice.verify_hash(randomHashBob));
        assertTrue(cliBob.verify_hash(randomHashAlice));

        String encodedTokenAlice = cliAlice.send_token_sp();  // This is the message the SP gets to blind sign given token
        String encodedTokenBob = cliBob.send_token_sp();      // This is the message the SP gets to blind sign given token

        String blindedTokenAlice = cliSP.blindsigntoken(encodedTokenAlice); // SP returns blind signed token
        String blindedTokenBob = cliSP.blindsigntoken(encodedTokenBob);     // --"--

        cliAlice.receive_blindtoken_sp(blindedTokenAlice);
        cliBob.receive_blindtoken_sp(blindedTokenBob);

        String[] tokensAlice = cliAlice.send_token_user();  // Alice creates the message to exchange the reputation token to bob
        String[] tokensBob = cliBob.send_token_user();      // Bob -----"------ to alice

        // To rate Bob Alice uses the tokens from bob
        // to verify the signature, alice uses her send_randomhash
        this.cliAlice.rate_user(4.0f, "Smooth and fast transaction", tokensBob[0], tokensBob[1]);
        this.cliBob.rate_user(5.0f, "Everything fine", tokensAlice[0], tokensAlice[1]);

        assertThat(this.cliSP.rate(4.0f, "Smooth and fast transaction", tokensBob[0], tokensBob[1], randomHashAlice)).isEqualTo("OK");
        assertThat(this.cliSP.rate(5.0f, "Everything fine", tokensAlice[0], tokensAlice[1], randomHashBob)).isEqualTo("OK");

        this.cliSP.showrating(this.cliAlice.userid());
    }

    @Test
    public void test_fail_rate_sametoken() throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, IOException, NoSuchProviderException {
        String randomHashAlice = cliAlice.send_randomhash();
        String randomHashBob = cliBob.send_randomhash();

        cliAlice.receive_hash(randomHashBob);   // alice recieves bob's random send_randomhash
        cliBob.receive_hash(randomHashAlice);   // bob recieves alice's random send_randomhash

        assertTrue(cliAlice.verify_hash(randomHashBob));
        assertTrue(cliBob.verify_hash(randomHashAlice));

        String encodedTokenAlice = cliAlice.send_token_sp();  // This is the message the SP gets to blind sign given token
        String encodedTokenBob = cliBob.send_token_sp();      // This is the message the SP gets to blind sign given token

        String blindedTokenAlice = cliSP.blindsigntoken(encodedTokenAlice); // SP returns blind signed token
        String blindedTokenBob = cliSP.blindsigntoken(encodedTokenBob);     // --"--

        cliAlice.receive_blindtoken_sp(blindedTokenAlice);
        cliBob.receive_blindtoken_sp(blindedTokenBob);

        String[] tokensAlice = cliAlice.send_token_user();  // Alice creates the message to exchange the reputation token to bob
        String[] tokensBob = cliBob.send_token_user();      // Bob -----"------ to alice

        // To rate Bob Alice uses the tokens from bob
        // to verify the signature, alice uses her send_randomhash
        this.cliAlice.rate_user(4.0f, "Smooth and fast transaction", tokensBob[0], tokensBob[1]);
        this.cliBob.rate_user(5.0f, "Everything fine", tokensAlice[0], tokensAlice[1]);

        assertThat(this.cliSP.rate(4.0f, "Smooth and fast transaction", tokensBob[0], tokensBob[1], randomHashAlice)).isEqualTo("OK");

        // We rate the same person 3 times with the same token
        assertThat(this.cliSP.rate(5.0f, "Everything fine", tokensAlice[0], tokensAlice[1], randomHashBob)).isEqualTo("OK");
        assertThat(this.cliSP.rate(5.0f, "Everything fine", tokensAlice[0], tokensAlice[1], randomHashBob)).isEqualTo("FAILED - Token already used");
        assertThat(this.cliSP.rate(5.0f, "Everything fine", tokensAlice[0], tokensAlice[1], randomHashBob)).isEqualTo("FAILED - Token already used");

        assertThat(this.cliSP.showrating(this.cliAlice.userid())).isEqualTo("5.0");
        assertThat(this.cliSP.showrating(this.cliBob.userid())).isEqualTo("4.0");
    }

    @Test
    public void test_rate_multiple() throws NoSuchProviderException, IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        String randomHashAlice = cliAlice.send_randomhash();
        String randomHashBob = cliBob.send_randomhash();

        cliAlice.receive_hash(randomHashBob);   // alice recieves bob's random send_randomhash
        cliBob.receive_hash(randomHashAlice);   // bob recieves alice's random send_randomhash

        assertTrue(cliAlice.verify_hash(randomHashBob));
        assertTrue(cliBob.verify_hash(randomHashAlice));

        String encodedTokenAlice = cliAlice.send_token_sp();  // This is the message the SP gets to blind sign given token
        String encodedTokenBob = cliBob.send_token_sp();      // This is the message the SP gets to blind sign given token

        String blindedTokenAlice = cliSP.blindsigntoken(encodedTokenAlice); // SP returns blind signed token
        String blindedTokenBob = cliSP.blindsigntoken(encodedTokenBob);     // --"--

        cliAlice.receive_blindtoken_sp(blindedTokenAlice);
        cliBob.receive_blindtoken_sp(blindedTokenBob);

        String[] tokensAlice = cliAlice.send_token_user();  // Alice creates the message to exchange the reputation token to bob
        String[] tokensBob = cliBob.send_token_user();      // Bob -----"------ to alice

        // To rate Bob Alice uses the tokens from bob
        // to verify the signature, alice uses her send_randomhash
        this.cliAlice.rate_user(4.0f, "Smooth and fast transaction", tokensBob[0], tokensBob[1]);
        this.cliBob.rate_user(5.0f, "Everything fine", tokensAlice[0], tokensAlice[1]);

        assertThat(this.cliSP.rate(4.0f, "Smooth and fast transaction", tokensBob[0], tokensBob[1], randomHashAlice)).isEqualTo("OK");
        assertThat(this.cliSP.rate(5.0f, "Everything fine", tokensAlice[0], tokensAlice[1], randomHashBob)).isEqualTo("OK");



        randomHashAlice = cliAlice.send_randomhash();
        String randomHashCarol = cliCarol.send_randomhash();

        cliAlice.receive_hash(randomHashCarol);   // alice recieves bob's random send_randomhash
        cliCarol.receive_hash(randomHashAlice);   // bob recieves alice's random send_randomhash

        assertTrue(cliAlice.verify_hash(randomHashCarol));
        assertTrue(cliCarol.verify_hash(randomHashAlice));

        encodedTokenAlice = cliAlice.send_token_sp();  // This is the message the SP gets to blind sign given token
        String encodedTokenCarol = cliCarol.send_token_sp();      // This is the message the SP gets to blind sign given token

        blindedTokenAlice = cliSP.blindsigntoken(encodedTokenAlice); // SP returns blind signed token
        String blindedTokenCarol = cliSP.blindsigntoken(encodedTokenCarol);     // --"--

        cliAlice.receive_blindtoken_sp(blindedTokenAlice);
        cliBob.receive_blindtoken_sp(blindedTokenBob);

        tokensAlice = cliAlice.send_token_user();  // Alice creates the message to exchange the reputation token to bob
        String[] tokensCarol = cliCarol.send_token_user();      // Bob -----"------ to alice

        // To rate Bob Alice uses the tokens from bob
        // to verify the signature, alice uses her send_randomhash
        this.cliAlice.rate_user(4.0f, "Smooth and fast transaction", tokensCarol[0], tokensCarol[1]);
        this.cliCarol.rate_user(3.0f, "Okay", tokensAlice[0], tokensAlice[1]);

        this.cliSP.rate(4.0f, "Smooth and fast transaction", tokensCarol[0], tokensCarol[1], randomHashAlice);
        this.cliSP.rate(3.0f, "Okay", tokensAlice[0], tokensAlice[1], randomHashCarol);


        randomHashAlice = cliAlice.send_randomhash();
        String randomHashCharlie = cliCharlie.send_randomhash();

        cliAlice.receive_hash(randomHashCharlie);   // alice recieves bob's random send_randomhash
        cliCharlie.receive_hash(randomHashAlice);   // bob recieves alice's random send_randomhash

        assertTrue(cliAlice.verify_hash(randomHashCharlie));
        assertTrue(cliCharlie.verify_hash(randomHashAlice));

        encodedTokenAlice = cliAlice.send_token_sp();  // This is the message the SP gets to blind sign given token
        String encodedTokenCharlie = cliCharlie.send_token_sp();      // This is the message the SP gets to blind sign given token

        blindedTokenAlice = cliSP.blindsigntoken(encodedTokenAlice); // SP returns blind signed token
        String blindedTokenCharlie = cliSP.blindsigntoken(encodedTokenCharlie);     // --"--

        cliAlice.receive_blindtoken_sp(blindedTokenAlice);
        cliBob.receive_blindtoken_sp(blindedTokenBob);

        tokensAlice = cliAlice.send_token_user();  // Alice creates the message to exchange the reputation token to bob
        String[] tokensCharlie = cliCharlie.send_token_user();      // Bob -----"------ to alice

        // To rate Bob Alice uses the tokens from bob
        // to verify the signature, alice uses her send_randomhash
        this.cliAlice.rate_user(4.0f, "Smooth and fast transaction", tokensCharlie[0], tokensCharlie[1]);
        this.cliCharlie.rate_user(1.0f, "Took too long (1 day)", tokensAlice[0], tokensAlice[1]);

        this.cliSP.rate(4.0f, "Smooth and fast transaction", tokensCharlie[0], tokensCharlie[1], randomHashAlice);
        this.cliSP.rate(1.0f, "Took too long (1 day)", tokensAlice[0], tokensAlice[1], randomHashCharlie);


        assertThat(this.cliSP.showrating(this.cliAlice.userid())).isEqualTo("3.0");
        System.out.println(this.cliSP.showallratings(this.cliAlice.userid()));
    }
}
