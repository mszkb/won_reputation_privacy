import SocketTest.Constants;
import SocketTest.TestBase;
import msz.Reputation.ReputationServer;
import msz.Signer.BlindSignature;
import msz.Signer.Signer;
import msz.TrustedParty.Params;
import msz.TrustedParty.TrustedParty;
import msz.User.Requestor;
import msz.User.Supplier;
import msz.Utils.HashUtils;
import msz.Utils.WrappedSocket;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

public class BlindSignatureTest extends TestBase {

    private Params params;
    private Requestor r;
    private Supplier s;
    private Signer sp;
    private BlindSignature blindSigner;

    private int reputationServicePort = 5555;
    private ReputationServer reputationServer;
    private Thread reputationServerThread;

    @Before
    public void createClients() throws InterruptedException, NoSuchProviderException, NoSuchAlgorithmException {
        this.params = new TrustedParty().generateParams();
        this.r = new Requestor(this.params);
        this.s = new Supplier(this.params);
        this.sp = new Signer(this.params);

        this.reputationServer = new ReputationServer(this.in, this.out, this.sp.getPublicKey());
        this.reputationServerThread = new Thread(reputationServer);
        this.reputationServerThread.start();
        Thread.sleep(Constants.COMPONENT_STARTUP_WAIT);

        this.blindSigner = new BlindSignature();
    }

    @Test
    public void test_blindSignature() {
        byte[] message = "My BLIND MESSAGE".getBytes(StandardCharsets.UTF_8);
        byte[] blindedSignature = this.blindSigner.blindAndSign(message);
        Assert.assertTrue(this.blindSigner.verify(blindedSignature, message));
    }

    @Test
    public void runSP_testBlindAndSign_valid() throws IOException, NoSuchAlgorithmException, InterruptedException {
        String randomHashAlice = HashUtils.generateRandomHash();

        WrappedSocket alice = new WrappedSocket("localhost", reputationServicePort, true);
        alice.writeOut("blindraw " + randomHashAlice);
        String blindedHash = alice.readIn();
        alice.writeOut("verifyraw " + blindedHash + " " + randomHashAlice);
        assertThat(alice.readIn(), is("valid"));
    }
    @Test
    public void runSP_testBlindAndSign_invalid() throws IOException, NoSuchAlgorithmException, InterruptedException {
        String randomHashAlice = HashUtils.generateRandomHash();

        WrappedSocket alice = new WrappedSocket("localhost", reputationServicePort, true);
        alice.writeOut("blindraw " + randomHashAlice);
        String blindedHash = alice.readIn();
        alice.writeOut("verifyraw " + blindedHash + " aaa" + randomHashAlice);
        assertThat(alice.readIn(), is("invalid"));
    }
}
