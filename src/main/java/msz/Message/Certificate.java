package msz.Message;

import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.util.Base64;

public class Certificate implements Message {
    private final static long serialVersionUID = 1;

    private PublicKey publicKey;   // user's public key
    private int ID;             // Account Information
    private byte[] signature;

    public Certificate(PublicKey publicKey, int ID, byte[] signature) {
        // TODO create public key
        // TODO insert into database
        // TODO ID from the insert
        this.publicKey = publicKey;
        this.ID = ID;
        this.signature = signature;
    }

    public PublicKey getPublicKey() {
        return this.publicKey;
    }

    public byte[] getBytes() {
        return (this.publicKey+","+ID).getBytes(StandardCharsets.UTF_8);
    }

    public byte[] getSignature() {
        return this.signature;
    }

    @Override
    public String toString() {
        return "Public Key is: " + this.publicKey + ", whith the registration ID: " + this.ID;
    }
}
