package msz.Signer;

import java.nio.charset.StandardCharsets;
import java.security.PublicKey;

public class Certificate {
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
        return publicKey;
    }

    public int getID() {
        return ID;
    }

    public byte[] getBytes() {
        return (this.publicKey+","+ID).getBytes(StandardCharsets.UTF_8);
    }

    public byte[] getSignature() {
        return this.signature;
    }
}
