package msz.Utils;

import msz.Reputation.ReputationBotServer;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;

public class WrappedSocket {
    private static final Log LOG = LogFactory.getLog(WrappedSocket.class);
    private Socket socket;

    private PrintWriter out;
    private BufferedReader in;


    public WrappedSocket(String host, int port){
        try {
            socket = new Socket(host, port);
            out = new PrintWriter(socket.getOutputStream(), true);
            in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        } catch (IOException e) {
            //e.printStackTrace();
        }
    }

    public Socket getSocket() {
        return socket;
    }

    public void writeOut(String msg){
        LOG.info(msg);
        out.println(msg);
    }

    public String readIn() throws IOException{
        String s = in.readLine();
        LOG.info(s);
        return s;
    }
}

