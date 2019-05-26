package msz.Reputation;

import msz.Message.Reputationtoken;
import msz.Signer.BlindSignature;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.Buffer;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

public class ReputationService implements IReputationServer {
    private ReputationStore reputationStore = null;
    private static final Log LOG = LogFactory.getLog(ReputationService.class);

    private final int servicePort = 5555;

    // TODO replace reputation hashmap with the reference to the store
    private ConcurrentHashMap<Integer, List<Reputation>> reputation = new ConcurrentHashMap<Integer, List<Reputation>>();
    private BlindSignature blindingHelper = new BlindSignature();
    private ServerSocket bobSocket;
    private Socket socket;
    private BufferedReader incMsgAlice;
    private PrintWriter outMsgAlice;

    private BufferedReader in;
    private PrintWriter out;

    public ReputationService(ReputationStore reputationStore, Socket socket) {
        this.reputationStore = reputationStore;
        this.socket = socket;
        try {
            this.out = new PrintWriter(socket.getOutputStream(), true);
            this.in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public ReputationService() {

    }

    private void waitForAlice() throws IOException {
//        LOG.info("Wait for Alice, on port " + this.servicePort);
//        this.bobSocket = new ServerSocket(this.servicePort);
//        this.aliceSocket = this.bobSocket.accept();
//        LOG.info("Connection accepted");
//        this.incMsgAlice = new BufferedReader(new InputStreamReader(this.aliceSocket.getInputStream()));
//        this.outMsgAlice = new PrintWriter(this.aliceSocket.getOutputStream(), true);
    }

    // TODO need client handler
    @Override
    public void run() {
        try {
//            this.waitForAlice();
            this.commandDispatch();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void commandDispatch() throws Exception {
        String inputLine;
        while (!socket.isClosed() &&(inputLine = this.in.readLine()) != null) {
            LOG.info("Alice wrote something: " + inputLine);
            String[] parts = inputLine.split(" ");

            switch (parts[0]) {
                case "blind":
                    this.blindAndSign(parts[1].getBytes());
                    break;
                case "verify":
                    this.verify(parts[1].getBytes(), parts[2].getBytes());
                    break;
                case "rating":
                    this.addRating(parts[1], parts[2], parts[3], parts[4], parts[5]);
                    break;
                case "bye":
                    socket.close();
                    break;
            }
        }
    }

    @Override
    public void addRating(String forUser, String rating, String message, String blindRepuationToken, String originalHash) throws Exception {
        if(this.blindingHelper.verify(originalHash.getBytes(), blindRepuationToken.getBytes())) {
            throw new Exception("Reputationtoken is not valid");
        }

        int userId = Integer.parseInt(forUser);

        if (this.reputation.containsKey(userId)) {
            List<Reputation> list = this.reputation.get(userId);
            list.add(new Reputation(Float.parseFloat(rating), message, blindRepuationToken.getBytes()));
        } else {
            List<Reputation> newList = new ArrayList<>();
            newList.add(new Reputation(Float.parseFloat(rating), message, blindRepuationToken.getBytes()));
            this.reputation.put(userId, newList);
        }
    }

    public void verify(byte[] blindRepuationToken, byte[] originalHash) throws Exception {
        if(this.blindingHelper.verify(blindRepuationToken, originalHash)) {
            this.out.println("valid");
        } else {
            this.out.println("invalid");
            throw new Exception("Reputationtoken is not valid");
        }
    }

    @Override
    public byte[] blindAndSign(Reputationtoken token) {
        return this.blindingHelper.blindAndSign(token.getBytes());
    }

    public byte[] blindAndSign(byte[] tokenBytes) {
        byte[] blindSignature = this.blindingHelper.blindAndSign(tokenBytes);
        this.out.println(blindSignature);
        return blindSignature;
    }

    @Override
    public float getCurrentRating(int userId) {
        List<Reputation> reputationList = this.reputation.get(userId);
        float rating = 0;

        for(Reputation reputation : reputationList) {
            rating += reputation.getRating();
        }

        float avgRating = rating / reputationList.size();

        return avgRating;
    }

    @Override
    public List<Reputation> getReputations(int userId) {
        return this.reputation.get(userId);
    }
}
