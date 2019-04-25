package msz.Message;

import sun.reflect.generics.reflectiveObjects.NotImplementedException;

import java.nio.charset.StandardCharsets;

public class Reputationtoken implements Message {

    private final Certificate certificate;
    private final byte[] signatureOfHash;

    public Reputationtoken(Certificate certificate, byte[] signatureOfHash) {
        this.certificate = certificate;
        this.signatureOfHash = signatureOfHash;
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
}
