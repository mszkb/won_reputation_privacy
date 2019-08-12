package msz.bakk.protocol.Reputation;

import msz.bakk.cmd.Utils;
import msz.bakk.protocol.Message.Reputationtoken;
import msz.bakk.protocol.Signer.Signer;
import msz.bakk.protocol.Utils.MessageUtils;
import msz.bakk.protocol.Utils.RSAUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

public class ReputationService implements IReputationServer {
    private Signer serviceProvider;
    private AsymmetricKeyParameter systemPublicKey = null;
    private boolean standalone = false;
    private ReputationStore reputationStore = null;
    private static final Log LOG = LogFactory.getLog(ReputationService.class);

    private final int servicePort;

    // TODO replace reputation hashmap with the reference to the store
    private ConcurrentHashMap<Integer, List<Reputation>> reputation = new ConcurrentHashMap<Integer, List<Reputation>>();
    private ServerSocket bobSocket;
    private Socket socket;

    private BufferedReader in;
    private PrintWriter out;

    public ReputationService(ReputationStore reputationStore, Socket socket, Signer serviceProvider) {
        this(5555);
        this.serviceProvider = serviceProvider;
        this.socket = socket;
        this.systemPublicKey = this.serviceProvider.getPublicSignatureKey();
        try {
            this.in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            this.out = new PrintWriter(socket.getOutputStream(), true);
            this.out.println("hi");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public ReputationService() {
        this(5555);
        this.standalone = true;
    }

    public ReputationService(int port) {
        this.servicePort = port;
    }

    private void waitForAlice() throws IOException {
        LOG.info("Wait for Alice, on port " + this.servicePort);
        this.bobSocket = new ServerSocket(this.servicePort);
        this.socket = this.bobSocket.accept();
        LOG.info("Connection accepted");
        this.in = new BufferedReader(new InputStreamReader(this.socket.getInputStream()));
        this.out = new PrintWriter(this.socket.getOutputStream(), true);
        this.out.println("hi");
    }

    @Override
    public void run() {
        try {
            if(standalone) {
                this.waitForAlice();
            }
            this.commandDispatch();
            LOG.info("Reputation Instance is closed");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void commandDispatch() throws Exception {
        String inputLine;
        while (!socket.isClosed() &&(inputLine = this.in.readLine()) != null) {
            LOG.info("Some User wrote us: " + inputLine);
            String[] parts = inputLine.split(" ");

            switch (parts[0]) {
                case "sign":
                    this.signBlind(parts[1]);
                    break;
                case "blindraw":
                    this.signBlind(parts[1].getBytes());
                    break;
                case "verify":
                    this.verify(
                            MessageUtils.decodeToBytes(parts[1]),
                            MessageUtils.decodeRT(parts[2]),
                            parts[3]);
                    break;
                case "verifyraw":
                    this.verify(MessageUtils.decodeToBytes(parts[1]), parts[2].getBytes());
                    break;
                case "rating":
                    this.addRating(parts[1], parts[2], parts[3], parts[4], parts[5], parts[6]);
                    break;
                case "bye":
                    this.tearDown();
                    break;
            }
        }
    }

    private void tearDown() {
        try {
            if(bobSocket != null) {
                bobSocket.close();
            }

            if(socket != null) {
                socket.close();
            }
        } catch (IOException e) {
            LOG.debug("Socket ist closed! This might be normal, here is the stackstrace anyways: " + e);
        }
    }

    @Override
    public void addRating(String forUser, String rating, String message, String blindRepuationToken, String originalHash, String originalReputationToken) throws Exception {
        if(this.serviceProvider.verify(originalHash.getBytes(), blindRepuationToken.getBytes())) {
            throw new Exception("Reputationtoken is not valid");
        }

        int userId = Integer.parseInt(forUser);

        if (this.reputation.containsKey(userId)) {
            List<Reputation> list = this.reputation.get(userId);
            list.add(new Reputation(Float.parseFloat(rating), message, blindRepuationToken.getBytes(), MessageUtils.decodeRT(originalReputationToken)));
        } else {
            List<Reputation> newList = new ArrayList<>();
            newList.add(new Reputation(Float.parseFloat(rating), message, blindRepuationToken.getBytes(), MessageUtils.decodeRT(originalReputationToken)));
            this.reputation.put(userId, newList);
        }
    }

    public void verify(byte[] blindRepuationToken, byte[] originalHash) throws Exception {
        if(this.serviceProvider.verify(blindRepuationToken, originalHash)) {
            this.out.println("valid");
            LOG.info("Reputationtoken is valid");
        } else {
            this.out.println("invalid");
            LOG.info("Reputationtoken is not valid");
        }
    }

    public void verify(byte[] blindRepuationToken, Reputationtoken reputationtoken) throws Exception {
        if(this.serviceProvider.verify(blindRepuationToken, reputationtoken.getBytes())) {
            this.out.println("valid");
            LOG.info("Reputationtoken is valid");
        } else {
            this.out.println("invalid");
            LOG.info("Reputationtoken is not valid");
        }
    }
    public void verify(byte[] unblindRepuationToken, Reputationtoken reputationtoken, String original) throws Exception {
        if(this.serviceProvider.verify(unblindRepuationToken, reputationtoken.getBytes())) {
            if(RSAUtils.verifySignature(reputationtoken.getSignatureOfHash(), Utils.generateHash(original), reputationtoken.getPubkeyFromCert())) {
                this.out.println("valid");
                LOG.info("Reputationtoken is valid");
            }
        }
        this.out.println("invalid");
        LOG.info("Reputationtoken is not valid");
    }

    @Override
    public String signBlind(String blindedToken) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        String blindSignature = this.signBlind(MessageUtils.decodeToBytes(blindedToken));

        this.out.println(blindSignature);
        return blindSignature;
    }

    public String signBlind(byte[] tokenBytes) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        return MessageUtils.encodeBytes(this.serviceProvider.signBlindMessage(tokenBytes));
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
