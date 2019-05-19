package msz.Reputation;

import msz.ConnectionHandler;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Reputation bot server listens for incoming connection
 * The connection is delegated to RepuationBotService
 * RepuationBotService is executed in a seperate Thread
 * to ensure that the whole process is non-blocking
 *
 * Thanks to 'distributed systems' at TU Wien for providing
 * the template and the test environment
 *
 * The shell listens for 'shutdown' to turn the server down
 * or just kill the process.
 */
public class ReputationBotServer extends Thread {
    private static final Log LOG = LogFactory.getLog(ReputationBotServer.class);

    private ExecutorService executor = Executors.newFixedThreadPool(10);

    private ServerSocket serverSocket;
    private boolean shutdown = false;

    private InputStream in;
    private PrintStream out;

    private int port = 5050;

    /**
     * This constructor takes the system shell for
     * reading and writing
     *
     * Start with standard port 5050
     */
    public ReputationBotServer() {
        this.in = System.in;
        this.out = System.out;
    }

    /**
     * This constructor takes a give input and printstream
     * Ideal for testing purpose
     *
     * @param in
     * @param out
     */
    public ReputationBotServer(InputStream in, PrintStream out, int port) {
        this.in = in;
        this.out = out;
        this.port = port;
    }

    /**
     * This starts a socket on port 5050 and listens
     * for shutdown.
     */
    @Override
    public void run() {
        try {
            // Create server socket for incomming connections to port 5050
            this.serverSocket = new ServerSocket(this.port);

            // listens for 'shutdown'
            this.directTerminal();
        } catch (InterruptedException | IOException e) {
            e.printStackTrace();
        }

        // Start Socket on port 5050
        // Listen for incomming connection to delegate
        // the handling to RepuationBotService
        new Thread(new RepuationBotConnection()).start();
    }

    /**
     * Inner class to make Threading possible to avoid creating spereated files
     * Starts the TransferClientHandler Thread after Client connects to
     * given ipadress and port
     */
    private class RepuationBotConnection implements ConnectionHandler {
        public void run() {
            try {
                clientAcceptLoop();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        /**
         * We wait for incoming connections and delegate the handling
         * to the Thread RepuationBotService
         *
         * @throws IOException
         */
        public void clientAcceptLoop() throws IOException {
            while(!serverSocket.isClosed()) {
                LOG.info("X Waiting for connection on port " + port);
                Socket socket = serverSocket.accept();
                IReputationBotService bot = new IReputationBotService();
                executor.execute(bot);
            }
        }
    }


    /**
     * Listen for "shutdown" keyword in the terminal and closes all sockets
     *
     * @throws InterruptedException
     * @throws IOException
     */
    private void directTerminal() throws InterruptedException, IOException {
        BufferedReader reader = new BufferedReader(new InputStreamReader(this.in));
        PrintWriter out = new PrintWriter(this.out);
        String inputLine;
        boolean shutdown = false;

        Thread.sleep(500); // Simulate some loading lol

        out.println("Shutdown the server with the command: 'shutdown'");
        out.print("T !> ");
        out.flush();

        while(!shutdown && (inputLine = reader.readLine()) != null) {
            if(inputLine.equals("shutdown")) {
                shutdown = true;
            }
        }
        this.shutdown();
    }

    /**
     * After recieving 'shutdown' we close all threads
     * including the server socket
     */
    private void shutdown() {
        this.out.println("Shutting down Reputationbot: " );    // TODO which transferserver?
        try {
            executor.shutdown();
            try {
                if (!executor.awaitTermination(800, TimeUnit.MILLISECONDS)) {
                    executor.shutdownNow();
                }
            } catch (InterruptedException e) {
                executor.shutdownNow();
            }
            this.serverSocket.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * For single test purpose and for easy start
     *
     * @param args
     */
    public static void main(String[] args) {
        new ReputationBotServer().start();
    }
}
