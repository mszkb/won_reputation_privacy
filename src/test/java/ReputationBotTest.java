import SocketTest.Constants;
import SocketTest.Sockets;
import SocketTest.TestBase;
import msz.Reputation.ReputationBot;
import org.junit.Test;

import java.net.SocketTimeoutException;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsNull.notNullValue;

public class ReputationBotTest extends TestBase {
    @Test
    public void runAndShutdownTransferServer_createsAndStopsTcpSocketCorrectly() throws Exception {
        ReputationBot bot = new ReputationBot();
        int port = 5050;

        assertThat(bot, is(notNullValue()));

        Thread componentThread = new Thread(bot);
        componentThread.start();

        try {
            Sockets.waitForSocket("localhost", port, Constants.COMPONENT_STARTUP_WAIT);
        } catch (SocketTimeoutException e) {
            err.addError(new AssertionError("Expected a TCP server socket on port " + port, e));
        }

        in.addLine("shutdown"); // send "shutdown" command to command line
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
