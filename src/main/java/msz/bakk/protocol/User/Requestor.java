package msz.bakk.protocol.User;

import msz.bakk.protocol.ACL;
import msz.bakk.protocol.Message.Message;
import msz.bakk.protocol.Message.Reputationtoken;
import msz.bakk.protocol.Signer.Signer;
import msz.bakk.protocol.TrustedParty.Params;
import msz.bakk.protocol.Utils.ECUtils;
import msz.bakk.protocol.Utils.HashUtils;
import msz.bakk.protocol.Utils.RSAUtils;
import msz.bakk.protocol.WonProtocol;
import org.bouncycastle.math.ec.ECPoint;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.sql.Timestamp;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.time.ZoneId;

/**
 * Requestor is considered as Alice
 */
public class Requestor implements ACL, WonProtocol {
    private final Params params;
    private msz.bakk.protocol.Message.Certificate certificate;
    private String foreignRandomHash;
    private KeyPair keyPair;
    private msz.bakk.protocol.Message.Certificate foreignCertificate;


    public Requestor(Params params) throws NoSuchProviderException {
        this.keyPair = ECUtils.generateKeyPair();

        this.params = params;
    }

    public Requestor(Params params, ECPoint y, Message m, String[] Attributes) throws NoSuchProviderException {
        this.keyPair = ECUtils.generateKeyPair();
        this.params = params;
    }

    /**
     * @source https://files.zotero.net/12620611427/From%20Zero%20Knowledge%20Proofs%20to%20Bulletproofs%20Paper%20.pdf
     */
    public ECPoint createCommitment(float reputation) {
        // use h0...hn for the combined Pedersen commitment
        // use z,h0...hn for the blinded Pedersen commitment

        // sum of the commitments h0 - hn is equivalent to commitment of (h0 + ... + hn)
        // C = generator * value + randomPoint * randomness
        // C = (C1 + ... + Cn) * randomness

        // multiply each attribute with the associated ECPoint in params (hs)
        // at the end add randomness * hs0

        ECPoint rnd = ECUtils.createRandomPoint(params.getGroup());

        // Expiration date is in 30 days at midnight
        // So our atom is valid for 30 days
        LocalTime midnight = LocalTime.MIDNIGHT;
        LocalDate today = LocalDate.now(ZoneId.of("Europe/Berlin"));
        LocalDateTime todayMidnight = LocalDateTime.of(today, midnight);
        LocalDateTime tomorrowMidnight = todayMidnight.plusDays(30);
        BigInteger exp = new BigInteger(String.valueOf(Timestamp.valueOf(tomorrowMidnight).getTime()));

        // multiply by 100 to make sure you have 2 two-digits behind the comma
        int irep = Math.round(reputation*100);
        BigInteger rep = new BigInteger(String.valueOf(irep));

        // This private key is associated with our certificates public key
        ECPrivateKey sk = (ECPrivateKey) this.keyPair.getPrivate();

        ECPoint commitment = rnd.multiply(sk.getS());
        commitment.multiply(exp);
        commitment.multiply(rep);

        return commitment;
    }

    private void createMessageToSign() {

    }

    public void setup() {
        createMessageToSign();
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
            this.certificate = sp.registerClient(this.keyPair.getPublic());
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
        return null;
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
        return RSAUtils.signString(this.keyPair, this.foreignRandomHash);
    }

    @Override
    public Reputationtoken createReputationToken(byte[] sigR) {
        // TODO s2ignHash
        // TODO create Reputationtoken with own cert and signature of Hash

        // TODO save blinded token in our instance for further checks
        return new Reputationtoken(this.certificate, sigR);
    }

    @Override
    public boolean verifySignature(byte[] signatureRandomHash, String sr, msz.bakk.protocol.Message.Certificate foreignCertificate) throws SignatureException, InvalidKeyException, NoSuchAlgorithmException {
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

    public Reputationtoken createReputationToken(msz.bakk.protocol.Message.Certificate certR, byte[] sigR) {
        return new Reputationtoken(certR, sigR);
    }
}
