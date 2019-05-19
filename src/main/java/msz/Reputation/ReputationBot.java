package msz.Reputation;

import msz.ConnectionHandler;
import msz.Message.Reputationtoken;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public class ReputationBot extends Thread implements ReputationServer {
    private static final Log LOG = LogFactory.getLog(ReputationBot.class);

    private ExecutorService executor = Executors.newFixedThreadPool(10);

    private ServerSocket serverSocket;
    private boolean shutdown = false;

    private InputStream in;
    private PrintStream out;

    public ReputationBot() {
    }

    public ReputationBot(InputStream in, PrintStream out) {
        this.in = in;
        this.out = out;
    }

    public void run() {
        try {
            this.serverSocket = new ServerSocket(5050);
        } catch (IOException e) {
            e.printStackTrace();
        }

        new Thread(new RepuationBotConnection()).start();

        // direct method listens for shutdown
        //
        try {
            this.direct();
        } catch (InterruptedException | IOException e) {
            e.printStackTrace();
        }
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
        public void clientAcceptLoop() throws IOException {
            while(!serverSocket.isClosed()) {
                LOG.info("X Waiting for connection on port " + 5050);
                Socket socket = serverSocket.accept();
//                executor.execute(ch);
            }
        }
    }


    /**
     * Listen for "shutdown" keyword in the terminal and closes all sockets
     *
     * @throws InterruptedException
     * @throws IOException
     */
    private void direct() throws InterruptedException, IOException {
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

    @Override
    public void addRating(int forUser, float rating, String message, byte[] blindToken, byte[] originalHash) throws Exception {

    }

    @Override
    public byte[] blindAndSign(Reputationtoken token) {
        return new byte[0];
    }

    @Override
    public float getCurrentRating(int userId) {
        return 0;
    }

    @Override
    public List<Reputation> getReputations(int userId) {
        return null;
    }

    public static void main(String[] args) {
        new ReputationBot(System.in, System.out).run();
    }
}
