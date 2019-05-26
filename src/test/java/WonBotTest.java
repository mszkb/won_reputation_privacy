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
import msz.Utils.ECUtils;
import msz.Utils.HashUtils;
import msz.Utils.RSAUtils;
import msz.Utils.WrappedSocket;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
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

    private IReputationServer reputationService;
    private int reputationServicePort = 5555;
    private TestInputStream repIn = new TestInputStream();
    private TestOutputStream repOut = new TestOutputStream();

    private ReputationBotBob bob;
    private Params params;
    private BlindSignature blindSigner;
    private Signer sp;

    @Before
    public void setUp() throws InterruptedException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
//        bot1 = new ReputationBotAlice("localhost", bobPort);
//        bot2 = new ReputationBotServer(this.bot2in, this.bot2out, bobPort, "bob");
        this.params = new TrustedParty().generateParams();
        this.sp = new Signer(this.params);
        this.blindSigner = new BlindSignature();

        KeyPair bobKeyPair = ECUtils.generateKeyPair();
        Certificate certBob = this.sp.registerClient(bobKeyPair.getPublic());
        bob = new ReputationBotBob(bot1in, bot1out, certBob);

        reputationService = new ReputationService();
        Thread reputationServiceThread = new Thread(reputationService);
        reputationServiceThread.start();

        Thread bobThread = new Thread(bob);
        bobThread.start();

//        new Thread(transfer).start();
//        new Thread(component).start();
//        new Thread(componentU).start();
//        Sockets.waitForSocket("localhost", port, Constants.COMPONENT_STARTUP_WAIT);
    }

    /**
     * Tests the blind signing and verifying part
     *
     * @throws IOException
     * @throws NoSuchAlgorithmException
     */
    @Test
    public void runSP_testBlindAndSign_valid() throws IOException, NoSuchAlgorithmException {
        String randomHashAlice = HashUtils.generateRandomHash();
        WrappedSocket alice = new WrappedSocket("localhost", reputationServicePort);
        alice.writeOut("blind " + randomHashAlice);
        String blindedHash = alice.readIn();
        alice.writeOut("verify " + blindedHash + " " + randomHashAlice);
        assertThat(alice.readIn(), is("valid"));
    }

    /**
     * Tests the blind signing and verifying part
     *
     * @throws IOException
     * @throws NoSuchAlgorithmException
     */
    @Test
    public void runSP_testBlindAndSign_invalid() throws IOException, NoSuchAlgorithmException {
        String randomHashAlice = HashUtils.generateRandomHash();
        WrappedSocket alice = new WrappedSocket("localhost", reputationServicePort);
        alice.writeOut("blind " + randomHashAlice);
        String blindedHash = alice.readIn();
        alice.writeOut("verify " + blindedHash + " randomFail");
        assertThat(alice.readIn(), is("invalid"));
    }

    /**
     * In this test case we run alice and test the protocol
     * on bob's side.
     *
     * @throws Exception
     */
    @Test
    public void runBob_testProtocol() throws Exception {
        // TODO Alice is our Thread which sends answers

        KeyPair aliceKeyPair = ECUtils.generateKeyPair();
        Certificate certAlice = this.sp.registerClient(aliceKeyPair.getPublic());
        String randomHashAlice = HashUtils.generateRandomHash();

        WrappedSocket alice = new WrappedSocket("localhost", bobPort);
        alice.writeOut("[1] " + randomHashAlice);

        // We wait for bobs answer - random hash
        String randomHashBob = alice.readIn().split(" ")[1];
        // sign the random hash from bob with our private key
        byte[] signedHashBob = RSAUtils.signString(aliceKeyPair, randomHashBob);
        // create repuation token for bob
        Reputationtoken tokenForBob = new Reputationtoken(certAlice, signedHashBob);
        // blind sign the reputation token by the SP
        byte[] blindedReputationToken = this.blindSigner.blindAndSign(tokenForBob.getBytes());
        // send reputation-token to bob
        alice.writeOut("[2] " + blindedReputationToken + " " + randomHashAlice);

        // we wait for bobs answer - reputation token
        String blindedRepuationTokenFromBob = alice.readIn();

        WrappedSocket sp = new WrappedSocket("localhost", reputationServicePort);
        sp.writeOut("verify " + blindedRepuationTokenFromBob + " " + randomHashAlice);
        assertThat(sp.readIn(), is("valid"));
        sp.writeOut("rating ");
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
