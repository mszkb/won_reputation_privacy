package msz.Reputation;

import msz.ConnectionHandler;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

/**
 * Reputation server listens for incoming bot connection
 * The connection is delegated to RepuationService
 * RepuationService is executed in a seperate Thread
 * to ensure that the whole process is non-blocking
 *
 * Only the bot knows the connection of this service
 *
 * Thanks to 'distributed systems' at TU Wien for providing
 * the template and the test environment
 *
 * The shell listens for 'shutdown' to turn the server down
 * or just kill the process.
 */
public class ReputationServer extends Thread {
    private static final Log LOG = LogFactory.getLog(ReputationServer.class);

    private ExecutorService executor = Executors.newFixedThreadPool(10);

    private ServerSocket serverSocket;
    private boolean shutdown = false;

    private InputStream in;
    private PrintStream out;

    private int port = 5555;

    private ReputationStore reputationStore = new ReputationStore();

    public ReputationServer() {
        this.in = System.in;
        this.out = System.out;
    }

    public ReputationServer(InputStream in, PrintStream out) {
        // For testing the server itself, use the Streams from the Testbase class
        this.in = in;
        this.out = out;
    }

    @Override
    public void run() {
        try {
            this.serverSocket = new ServerSocket(this.port);
            new Thread(new RepuationServerConnection()).start();
            this.directTerminal();
        } catch (InterruptedException | IOException e) {
            e.printStackTrace();
        }
    }

    private class RepuationServerConnection implements ConnectionHandler {
        public void run() {
            try {
                clientAcceptLoop();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        // We wait for incoming connections and delegate the handling
        // to the Thread RepuationBotService
        public void clientAcceptLoop() throws IOException {
            while(!serverSocket.isClosed()) {
                LOG.info("X Waiting for connection on port " + port);
                Socket socket = serverSocket.accept();
                ReputationService service = new ReputationService(reputationStore, socket);
                LOG.info("We spawn a new service thread");
                executor.execute(service);
            }
        }
    }

    // Listen for "shutdown" keyword in the terminal and closes all sockets
    private void directTerminal() throws InterruptedException, IOException {
        BufferedReader reader = new BufferedReader(new InputStreamReader(this.in));
        PrintWriter out = new PrintWriter(this.out);
        String inputLine;
        boolean shutdown = false;

        Thread.sleep(500); // Simulate some loading

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

    //After recieving 'shutdown' we close all threads
    //including the server socket
    private void shutdown() {
        this.out.println("Shutting down Reputationbot: " );
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

    //For single test purpose and for easy start
    public static void main(String[] args) {
        new ReputationServer().start();
    }
}
