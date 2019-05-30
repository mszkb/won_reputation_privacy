package msz.Message;

import java.io.Serializable;

public interface Message extends Serializable {
    byte[] getBytes();
    byte[] getSignature();
}
