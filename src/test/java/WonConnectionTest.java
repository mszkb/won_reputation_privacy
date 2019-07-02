import SocketTest.Constants;
import SocketTest.Sockets;
import SocketTest.TestBase;
import msz.Reputation.ReputationServer;
import msz.Signer.Signer;
import msz.TrustedParty.Params;
import msz.TrustedParty.TrustedParty;
import org.junit.Before;
import org.junit.Test;

import java.net.SocketTimeoutException;
import java.security.NoSuchAlgorithmException;

import static org.hamcrest.CoreMatchers.is;

public class WonConnectionTest extends TestBase {

    private final int reputationServicePort = 5555;
    private Params params;
    private Signer sp;

    @Before
    public void setUp() throws NoSuchAlgorithmException {
        this.params = new TrustedParty().generateParams();
        this.sp = new Signer(this.params);
    }

    @Test
    public void connectionTest() throws Exception {
        ReputationServer reputationServer = new ReputationServer(in, out, sp.getPublicKey());
        Thread bot1Thread = new Thread(reputationServer);
        bot1Thread.start();

        try {
            Sockets.waitForSocket("localhost", reputationServicePort, Constants.COMPONENT_STARTUP_WAIT);
            // TODO wait for reputation server
        } catch (SocketTimeoutException e) {
            err.addError(new AssertionError("Expected a TCP server socket on port " + reputationServicePort, e));
        }

        in.addLine("shutdown");
        Thread.sleep(Constants.COMPONENT_TEARDOWN_WAIT);

        try {
            bot1Thread.join();
            // TODO join reputation server
        } catch (InterruptedException e) {
            err.addError(new AssertionError("Bot or server was not terminated correctly"));
        }
        err.checkThat("Expected tcp socket on port " + reputationServicePort + " to be closed after shutdown",
                Sockets.isServerSocketOpen(reputationServicePort), is(false));
    }
}
