package msz.Message;

import sun.reflect.generics.reflectiveObjects.NotImplementedException;

import java.nio.charset.StandardCharsets;
import java.security.PublicKey;

public class Reputationtoken implements Message {

    private final Certificate certificate;
    private final byte[] signatureOfHash;
    private final byte[] signatureOfReputationToken;

    public Reputationtoken(Certificate certificate, byte[] signatureOfHash, byte[] signatureOfReputationToken) {
        this.certificate = certificate;
        this.signatureOfHash = signatureOfHash;
        this.signatureOfReputationToken = signatureOfReputationToken;
    }

    @Override
    public byte[] getBytes() {
        String certificateString = new String(this.certificate.getBytes());
        String signatureOfHashString = new String(this.signatureOfHash);
        return (certificateString+","+signatureOfHashString).getBytes(StandardCharsets.UTF_8);
    }

    @Override
    public byte[] getSignature() {
        throw new NotImplementedException();
    }

    public byte[] getSignatureOfHash() {
        return this.signatureOfHash;
    }

    public PublicKey getPubkeyFromCert() {
        return this.certificate.getPublicKey();
    }

    public byte[] getBytesFromCert() {
        return this.certificate.getBytes();
    }

    public byte[] getSignatureFromCert() {
        return this.certificate.getSignature();
    }
}
