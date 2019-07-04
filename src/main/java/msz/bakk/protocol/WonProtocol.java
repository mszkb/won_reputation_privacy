package msz.bakk.protocol;

import msz.bakk.protocol.Message.Certificate;
import msz.bakk.protocol.Message.Reputationtoken;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;

public interface WonProtocol {
    Certificate registerWithSystem();
    Certificate getCertificate();

    String createRandomHash() throws NoSuchAlgorithmException;
    void exchangeHash(String randomHash);
    Reputationtoken createReputationToken(byte[] sig);
    byte[] signHash() throws NoSuchAlgorithmException, InvalidKeyException, UnsupportedEncodingException, SignatureException;
    boolean verifySignature(byte[] signatureRandomHash, String sr, Certificate cert) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException;

    void exchangeReputationToken(Reputationtoken RTs);
}
