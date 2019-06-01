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

    // setting wait to true waits until the server wrote something
    // when server has written something we know that she is ready
    public WrappedSocket(String host, int port, boolean wait){
        try {
            socket = new Socket(host, port);
            out = new PrintWriter(socket.getOutputStream(), true);
            in = new BufferedReader(new InputStreamReader(socket.getInputStream()));

            if(wait) {
                this.readIn();
            }
        } catch (Exception e) {
            e.printStackTrace();
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

    public byte[] readInBytes() throws IOException {
        byte[] b = new byte[256];
        int count = socket.getInputStream().read(b, 0 ,256);
        LOG.info(b);
        return b;
    }

    public void close() {
        try {
            socket.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}

