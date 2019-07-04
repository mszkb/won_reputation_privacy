package msz.bakk.protocol.User;

import msz.bakk.protocol.ACL;
import msz.bakk.protocol.Message.Reputationtoken;
import msz.bakk.protocol.Signer.Signer;
import msz.bakk.protocol.TrustedParty.Params;
import msz.bakk.protocol.Utils.ECUtils;
import msz.bakk.protocol.Utils.HashUtils;
import msz.bakk.protocol.WonProtocol;
import org.bouncycastle.math.ec.ECPoint;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.*;

/**
 * Supplier is considered as Bob
 */
public class Supplier implements ACL, WonProtocol {

    private Params params;
    private msz.bakk.protocol.Message.Certificate certificate;
    private String foreignRandomHash;
    private KeyPair keyPair;
    private msz.bakk.protocol.Message.Certificate foreignCertificate;

    public Supplier() throws NoSuchProviderException {
        this.keyPair = ECUtils.generateKeyPair();
    }

    public Supplier(Params params) {
        this.keyPair = ECUtils.generateKeyPair();
        this.params = params;
    }

    public void setup() {

    }

    public void registration(ECPoint commitment) {

    }

    public void preparation() {

    }

    public void validation() {

    }

    public void verifiction() {

    }

    public msz.bakk.protocol.Message.Certificate registerWithSystem(Signer sp) {
        try {
            this.certificate = sp.registerClient(keyPair.getPublic());
            return this.certificate;
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            e.printStackTrace();
        }
        return null;
    }

    @Override
    public msz.bakk.protocol.Message.Certificate registerWithSystem() {
        return null;
    }

    @Override
    public msz.bakk.protocol.Message.Certificate getCertificate() {
        return this.certificate;
    }

    @Override
    public String createRandomHash() throws NoSuchAlgorithmException {
        return HashUtils.generateRandomHash();
    }

    @Override
    public void exchangeHash(String randomHash) {
        this.foreignRandomHash = randomHash;
    }

    @Override
    public byte[] signHash() throws NoSuchAlgorithmException, InvalidKeyException, UnsupportedEncodingException, SignatureException {
        // TODO sign Hash with the publickey of the certificate
        Signature signatureOfRandomHash = Signature.getInstance("SHA256withECDSA");
        signatureOfRandomHash.initSign(this.keyPair.getPrivate());
        signatureOfRandomHash.update(this.foreignRandomHash.getBytes(StandardCharsets.UTF_8));
        return signatureOfRandomHash.sign();
    }

    @Override
    public Reputationtoken createReputationToken(byte[] sigS) {
        // TODO signHash
        // TODO create Reputationtoken with own cert and signature of Hash
        return new Reputationtoken(this.certificate, sigS);
    }

    @Override
    public boolean verifySignature(byte[] signatureRandomHash, String sr, msz.bakk.protocol.Message.Certificate foreignCertificate) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        boolean isHashCorrect;

        Signature verifySignature = Signature.getInstance("SHA256withECDSA");
        verifySignature.initVerify(foreignCertificate.getPublicKey());
        verifySignature.update(sr.getBytes(StandardCharsets.UTF_8));
        isHashCorrect = verifySignature.verify(signatureRandomHash);

        if(isHashCorrect) {
            this.foreignCertificate = foreignCertificate;
        }

        return isHashCorrect;
    }

    @Override
    public void exchangeReputationToken(Reputationtoken RTs) {

    }

    public Reputationtoken createReputationToken(msz.bakk.protocol.Message.Certificate certS, byte[] sigS) {
        return new Reputationtoken(certS, sigS);
    }
}
