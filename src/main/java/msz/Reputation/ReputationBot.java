package msz.Reputation;

import msz.Message.Reputationtoken;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.List;

public class ReputationBot extends Thread implements ReputationServer {

    private ServerSocket serverSocket;

    public ReputationBot() {

    }

    public void run() {
        String ipaddress = "localhost";
        int port = 5050;

        try {
            this.serverSocket = new ServerSocket(port);
        } catch (IOException e) {
            e.printStackTrace();
        }
        Socket socket = null;
        try {
            socket = this.serverSocket.accept();
        } catch (IOException e) {
            e.printStackTrace();
        }

        try {
            PrintWriter out = new PrintWriter(socket.getOutputStream());
        } catch (IOException e) {
            e.printStackTrace();
        }
        try {
            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        } catch (IOException e) {
            e.printStackTrace();
        }

        while(!shutdown && (inputLine = in.readLine()) != null) {
            if(inputLine.equals("shutdown")) {
                shutdown = true;
            }
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
}
