import SocketTest.*;
import msz.Reputation.ReputationBot;
import org.junit.Before;
import org.junit.Test;

import java.net.SocketTimeoutException;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsNull.notNullValue;

public class ReputationBotTest extends TestBase {

    private TestInputStream tIn = new TestInputStream();
    private TestInputStream inU = new TestInputStream();
    private TestOutputStream tOut = new TestOutputStream();
    private TestOutputStream outU = new TestOutputStream();

    private int directPort = 5050;
    private int port = 5055;

    private ReputationBot bot1;

    @Before
    public void setUp() throws Exception {

        bot1 = new ReputationBot(tIn, tOut);
//        new Thread(transfer).start();
//        new Thread(component).start();
//        new Thread(componentU).start();
//        Sockets.waitForSocket("localhost", port, Constants.COMPONENT_STARTUP_WAIT);
    }

    @Test
    public void runAndShutdownTransferServer_createsAndStopsTcpSocketCorrectly() throws Exception {
        assertThat(bot1, is(notNullValue()));

        Thread componentThread = new Thread(bot1);
        componentThread.start();

        try {
            Sockets.waitForSocket("localhost", directPort, Constants.COMPONENT_STARTUP_WAIT);
        } catch (SocketTimeoutException e) {
            err.addError(new AssertionError("Expected a TCP server socket on port " + directPort, e));
        }

        tIn.addLine("shutdown"); // send "shutdown" command to command line
        Thread.sleep(Constants.COMPONENT_TEARDOWN_WAIT);

        try {
            componentThread.join();
        } catch (InterruptedException e) {
            err.addError(new AssertionError("Transfer server was not terminated correctly"));
        }

        err.checkThat("Expected tcp socket on port " + port + " to be closed after shutdown",
                Sockets.isServerSocketOpen(port), is(false));
    }
}
