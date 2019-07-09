import SocketTest.Constants;
import SocketTest.TestBase;
import msz.bakk.protocol.Reputation.ReputationServer;
import msz.bakk.protocol.Signer.BlindSignature;
import msz.bakk.protocol.Signer.Signer;
import msz.bakk.protocol.TrustedParty.Params;
import msz.bakk.protocol.TrustedParty.TrustedParty;
import msz.bakk.protocol.User.Requestor;
import msz.bakk.protocol.User.Supplier;
import msz.bakk.protocol.Utils.HashUtils;
import msz.bakk.protocol.Utils.WrappedSocket;
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

    public void test_blindSignature() {
        byte[] message = "My BLIND MESSAGE".getBytes(StandardCharsets.UTF_8);
        byte[] blindedSignature = this.blindSigner.blindAndSign(message);
        Assert.assertTrue(this.blindSigner.verify(blindedSignature, message));
    }

    public void runSP_testBlindAndSign_valid() throws IOException, NoSuchAlgorithmException, InterruptedException {
        String randomHashAlice = HashUtils.generateRandomHash();

        WrappedSocket alice = new WrappedSocket("localhost", reputationServicePort, true);
        alice.writeOut("blindraw " + randomHashAlice);
        String blindedHash = alice.readIn();
        alice.writeOut("verifyraw " + blindedHash + " " + randomHashAlice);
        assertThat(alice.readIn(), is("valid"));
    }

    public void runSP_testBlindAndSign_invalid() throws IOException, NoSuchAlgorithmException, InterruptedException {
        String randomHashAlice = HashUtils.generateRandomHash();

        WrappedSocket alice = new WrappedSocket("localhost", reputationServicePort, true);
        alice.writeOut("blindraw " + randomHashAlice);
        String blindedHash = alice.readIn();
        alice.writeOut("verifyraw " + blindedHash + " aaa" + randomHashAlice);
        assertThat(alice.readIn(), is("invalid"));
    }
}
