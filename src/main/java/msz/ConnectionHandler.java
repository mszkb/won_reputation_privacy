package msz;

import java.io.IOException;

public interface ConnectionHandler extends Runnable {
    /**
     * This method is used by the Thead class to execute the instance
     * You should always call clientAcceptLoop() in this method
     */
    void run();

    /**
     * Takes care of Thread creation and connection accepting
     *
     * @throws IOException - server socket is closed
     */
    void clientAcceptLoop() throws IOException;
}

