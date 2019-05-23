import SocketTest.*;
import msz.Reputation.ReputationBotServer;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.net.SocketTimeoutException;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsNull.notNullValue;

/**
 * This test class can be considered as the client
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
public class ReputationBotTest extends TestBase {

    private TestInputStream bot1in = new TestInputStream();
    private TestOutputStream bot1out = new TestOutputStream();

    private TestInputStream bot2in = new TestInputStream();
    private TestOutputStream bot2out = new TestOutputStream();

    private ReputationBotServer bot1;
    private int bot1port = 5050;

    private ReputationBotServer bot2;
    private int bot2port = 5051;

    @Before
    public void setUp() {
        bot1 = new ReputationBotServer(bot1in, bot1out, bot1port);
        bot2 = new ReputationBotServer(bot2in, bot2out, bot2port);
//        new Thread(transfer).start();
//        new Thread(component).start();
//        new Thread(componentU).start();
//        Sockets.waitForSocket("localhost", port, Constants.COMPONENT_STARTUP_WAIT);
    }

    @Test
    public void runAndShutdownBots_createsAndStopsTcpSocketCorrectly() throws Exception {
        assertThat(bot1, is(notNullValue()));

        Thread bot1Thread = new Thread(bot1);
        Thread bot2Thread = new Thread(bot2);
        bot1Thread.start();
        bot2Thread.start();

        try {
            Sockets.waitForSocket("localhost", bot1port, Constants.COMPONENT_STARTUP_WAIT);
            Sockets.waitForSocket("localhost", bot2port, Constants.COMPONENT_STARTUP_WAIT);
        } catch (SocketTimeoutException e) {
            err.addError(new AssertionError("Expected a TCP server socket on port " + bot1port, e));
            err.addError(new AssertionError("Expected a TCP server socket on port " + bot2port, e));
        }

        bot1in.addLine("shutdown"); // send "shutdown" command to command line
        bot2in.addLine("shutdown"); // send "shutdown" command to command line
        Thread.sleep(Constants.COMPONENT_TEARDOWN_WAIT);

        try {
            bot1Thread.join();
            bot2Thread.join();
        } catch (InterruptedException e) {
            err.addError(new AssertionError("Bots were not terminated correctly"));
        }
        err.checkThat("Expected tcp socket on port " + bot1port + " to be closed after shutdown",
                Sockets.isServerSocketOpen(bot1port), is(false));

        err.checkThat("Expected tcp socket on port " + bot2port + " to be closed after shutdown",
                Sockets.isServerSocketOpen(bot2port), is(false));
    }

    @Test
    public void botsConnectToRepuationServer() throws Exception {
        Thread bot1Thread = new Thread(bot1);
        Thread bot2Thread = new Thread(bot2);
        bot1Thread.start();
        bot2Thread.start();

        // TODO  start reputation server thread

        try {
            Sockets.waitForSocket("localhost", bot1port, Constants.COMPONENT_STARTUP_WAIT);
            Sockets.waitForSocket("localhost", bot2port, Constants.COMPONENT_STARTUP_WAIT);
            // TODO wait for reputation server

        } catch (SocketTimeoutException e) {
            err.addError(new AssertionError("Expected a TCP server socket on port " + bot1port, e));
            err.addError(new AssertionError("Expected a TCP server socket on port " + bot2port, e));
        }





















        bot1in.addLine("shutdown");
        bot2in.addLine("shutdown"); // send "shutdown" command to command line
        Thread.sleep(Constants.COMPONENT_TEARDOWN_WAIT);

        try {
            bot1Thread.join();
            bot2Thread.join();
            // TODO join reputation server
        } catch (InterruptedException e) {
            err.addError(new AssertionError("Bot or server was not terminated correctly"));
        }
        err.checkThat("Expected tcp socket on port " + bot1port + " to be closed after shutdown",
                Sockets.isServerSocketOpen(bot1port), is(false));
        err.checkThat("Expected tcp socket on port " + bot2port + " to be closed after shutdown",
                Sockets.isServerSocketOpen(bot2port), is(false));
    }
}
