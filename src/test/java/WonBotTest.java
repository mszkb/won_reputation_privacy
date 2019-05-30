import SocketTest.*;
import msz.Message.Certificate;
import msz.Message.Reputationtoken;
import msz.Reputation.*;
import msz.Signer.BlindSignature;
import msz.Signer.Signer;
import msz.TrustedParty.Params;
import msz.TrustedParty.TrustedParty;
import msz.User.Requestor;
import msz.User.Supplier;
import msz.Utils.*;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Arrays;
import java.util.Base64;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsNull.notNullValue;
import static org.junit.Assert.assertTrue;

/**
 *
 * The client wants to rate another client. That's whats going on:
 *
 * 1) client generates a random number, hashes it and sends it to the bot
 * 2) the bot sends the hash to another bot and recieves a hashed random number from the other bot
 * 3) the bot signs the hash
 * 4) the bot sends the signed hash and the cerificate of the user to the RepuationServer
 * 5) the reputationserver creates a blind signature of the signed hash and the certificate and sends back to the bot
 * 6) the bot sends the blind signature to the other bot and recieves a blind signature
 * 7) the bot verifies with the repuationserver if the recieved siganture is valid
 */
public class WonBotTest extends TestBase {
    private static final Log LOG = LogFactory.getLog(WonBotTest.class);

    private TestInputStream bot1in = new TestInputStream();
    private TestOutputStream bot1out = new TestOutputStream();

    private TestInputStream bot2in = new TestInputStream();
    private TestOutputStream bot2out = new TestOutputStream();

    private IRepuationBot bot1;
    private int alicePort = 5050;

    private ReputationBotServer bot2;
    private int bobPort = 5055;

    private ReputationService reputationService;
    private int reputationServicePort = 5555;
    private TestInputStream repIn = new TestInputStream();
    private TestOutputStream repOut = new TestOutputStream();

    private ReputationBotBob bob;
    private Params params;
    private BlindSignature blindSigner;
    private Signer sp;
    private Thread bobThread;
    private Thread reputationServiceThread;

    @Before
    public void setUp() throws InterruptedException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
//        bot1 = new ReputationBotAlice("localhost", bobPort);
//        bot2 = new ReputationBotServer(this.bot2in, this.bot2out, bobPort, "bob");
        this.params = new TrustedParty().generateParams();
        this.sp = new Signer(this.params);
        this.blindSigner = new BlindSignature();

        this.reputationService = new ReputationService();
        this.reputationServiceThread = new Thread(reputationService);

        KeyPair bobKeyPair = ECUtils.generateKeyPair();
        Certificate certBob = this.sp.registerClient(bobKeyPair.getPublic());
        this.bob = new ReputationBotBob(bot1in, bot1out, certBob);
        this.bobThread = new Thread(bob);

//        new Thread(transfer).start();
//        new Thread(component).start();
//        new Thread(componentU).start();
//        Sockets.waitForSocket("localhost", port, Constants.COMPONENT_STARTUP_WAIT);
    }

    @Test
    public void runSP_testBlindAndSign_valid() throws IOException, NoSuchAlgorithmException, InterruptedException {
        this.reputationServiceThread.start();

        // our test class proceeds too fast so we need to wait
        Thread.sleep(Constants.COMPONENT_STARTUP_WAIT);

        String randomHashAlice = HashUtils.generateRandomHash();
        WrappedSocket alice = new WrappedSocket("localhost", reputationServicePort);

        alice.readIn(); // we wait until server is ready - server sends "hi"
        alice.writeOut("blindraw " + randomHashAlice);
        String blindedHash = alice.readIn();
        alice.writeOut("verifyraw " + blindedHash + " " + randomHashAlice);
        assertThat(alice.readIn(), is("valid"));
    }
    @Test
    public void runSP_testBlindAndSign_invalid() throws IOException, NoSuchAlgorithmException, InterruptedException {
        this.reputationServiceThread.start();

        // our test class proceeds too fast so we need to wait
        Thread.sleep(Constants.COMPONENT_STARTUP_WAIT);

        String randomHashAlice = HashUtils.generateRandomHash();
        WrappedSocket alice = new WrappedSocket("localhost", reputationServicePort);

        alice.readIn(); // we wait until server is ready - server sends "hi"
        alice.writeOut("blindraw " + randomHashAlice);
        String blindedHash = alice.readIn();
        alice.writeOut("verifyraw " + blindedHash + " aaa" + randomHashAlice);
        assertThat(alice.readIn(), is("invalid"));
    }

    @Test
    public void runSP_testBlindAndSign_valid_reputationToken() throws InterruptedException, NoSuchAlgorithmException, IOException, NoSuchProviderException, InvalidAlgorithmParameterException, SignatureException, InvalidKeyException {
        this.reputationServiceThread.start();

        // our test class proceeds too fast so we need to wait
        Thread.sleep(Constants.COMPONENT_STARTUP_WAIT);

        // These are the steps to create a blind signature out of the Reputation-Token
        KeyPair aliceKeyPair        = ECUtils.generateKeyPair();
        Certificate certAlice       = this.sp.registerClient(aliceKeyPair.getPublic());
        String randomHashAlice      = HashUtils.generateRandomHash();
        String randomHashBob        = HashUtils.generateRandomHash();
        byte[] signedHashBob        = RSAUtils.signString(aliceKeyPair, randomHashBob);
        Reputationtoken tokenForBob = new Reputationtoken(certAlice, signedHashBob);
        String encodedToken         = MessageUtils.toString(tokenForBob);

        WrappedSocket alice = new WrappedSocket("localhost", reputationServicePort);
        alice.readIn(); // we wait until server is ready - server sends "hi"
        alice.writeOut("blind " + encodedToken);
        String blindedHash = alice.readIn();
        alice.writeOut("verify " + blindedHash + " " + encodedToken);
        assertThat(alice.readIn(), is("valid"));
    }

    /**
     * In this test case we run alice and test the protocol
     * on bob's side.
     */
    @Test
    public void runBob_testProtocol() throws Exception {
        this.reputationServiceThread.start();
        this.bobThread.start();
        Thread.sleep(Constants.COMPONENT_STARTUP_WAIT);

        // Alice is our Test-method, we begin to send Bob our random hash
        KeyPair aliceKeyPair = ECUtils.generateKeyPair();
        Certificate certAlice = this.sp.registerClient(aliceKeyPair.getPublic());
        String randomHashAlice = HashUtils.generateRandomHash();

        WrappedSocket alice = new WrappedSocket("localhost", bobPort);
        alice.readIn();
        alice.writeOut("[1] " + randomHashAlice);

        // We wait for bobs answer - random hash
        String randomHashBob = alice.readIn().split(" ")[1];
        // sign the random hash from bob with our private key
        byte[] signedHashBob = RSAUtils.signString(aliceKeyPair, randomHashBob);
        // create repuation token for bob
        Reputationtoken tokenForBob = new Reputationtoken(certAlice, signedHashBob);
        String encodedToken = MessageUtils.toString(tokenForBob);
        // blind sign the reputation token by the SP
        byte[] blindedReputationToken = this.blindSigner.blindAndSign(tokenForBob.getBytes());
        String blindRTinHex = MessageUtils.encodeBytes(blindedReputationToken);

        // send reputation-token to bob
        alice.writeOut("[2] " + blindRTinHex + " " + encodedToken);

        // we wait for bobs answer - reputation token
        String repuationTokenFromBob = alice.readIn();
        LOG.info("We got the reptoken from bob");

        this.reputationService = new ReputationService();
        this.reputationServiceThread.join();
        this.reputationServiceThread = new Thread(reputationService);
        this.reputationServiceThread.start();
        Thread.sleep(Constants.COMPONENT_STARTUP_WAIT);
        WrappedSocket sp = new WrappedSocket("localhost", reputationServicePort);
        LOG.info("Wait until Reputation service is ready");
        sp.readIn();
        sp.writeOut("verify " + repuationTokenFromBob + " " + encodedToken);
        assertThat(sp.readIn(), is("valid"));
        sp.writeOut("rating ");
        sp.close();
    }

    @Test
    public void runAlice_testProtocol() throws Exception {
        assertThat(bot1, is(notNullValue()));

        Thread bobThread = new Thread(bot2);
        bobThread.start();
        try {
            Sockets.waitForSocket("localhost", bobPort, Constants.COMPONENT_STARTUP_WAIT);
        } catch (SocketTimeoutException e) {
            err.addError(new AssertionError("Expected a TCP server socket on port " + bobPort, e));
        }

        Thread aliceThread = new Thread(bot1);
        aliceThread.start();

        // TODO here wait for Reputation token

        try (JunitSocketClient client = new JunitSocketClient(alicePort, err)) {
            client.verify("[4] repuationtoken");
        }

        try (JunitSocketClient client = new JunitSocketClient(bobPort, err)) {
            client.verify("[4] repuationtoken");
        }


        try {
            aliceThread.join();
            bobThread.join();
        } catch (InterruptedException e) {
            err.addError(new AssertionError("Bots were not terminated correctly"));
        }
        err.checkThat("Expected tcp socket on port " + alicePort + " to be closed after shutdown",
                Sockets.isServerSocketOpen(alicePort), is(false));

        err.checkThat("Expected tcp socket on port " + bobPort + " to be closed after shutdown",
                Sockets.isServerSocketOpen(bobPort), is(false));
    }


}
