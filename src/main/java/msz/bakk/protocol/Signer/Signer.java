package msz.bakk.protocol.Signer;

import msz.bakk.protocol.ACL;
import msz.bakk.protocol.Message.Reputationtoken;
import msz.bakk.protocol.TrustedParty.Params;
import msz.bakk.protocol.Utils.ECUtils;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.util.ArrayList;

public class Signer implements ACL {
    private Params params;
    private ECPoint x;
    private ECPoint y;

    private final PrivateKey privateKey;
    private final PublicKey publicKey;

    private ArrayList<PublicKey> clientList = new ArrayList<>();

    private ECPoint commitment;

    public Signer(Params params) throws NoSuchAlgorithmException {
        this.params = params;
        // Signer Keys
        KeyPair signerKP = null;
        signerKP = ECUtils.generateKeyPair();

        if(signerKP == null) {
            throw new NullPointerException("KeyPair generation Failed");
        }

        this.privateKey = signerKP.getPrivate();
        this.publicKey = signerKP.getPublic();
    }

    private void generateKeys() {
    }

    public PublicKey getPublicKey() {
        return this.publicKey;
    }

    public void setup() {
        // msz.Signer picks his secret key x and compute real public key y
        // the secret key is not a ssh key or somewhat, just a random point on the curve
        ECPoint[] keys = createSignersKeys();
        this.x = keys[0];
        this.y = keys[1];
    }

    public void registration(ECPoint commitment) {
        this.commitment = commitment;
        this.params = params;
        ECPrivateKey sk = (ECPrivateKey) this.privateKey;

        ECPoint rnd = ECUtils.createRandomPoint(this.params.getGroup());
        ECPoint z1 = rnd.add(this.commitment);
        ECPoint z2 = z1.subtract(this.params.getZ());
    }

    public void preparation() {

    }

    public void validation() {

    }

    public void verifiction() {

    }

    /**
     * The signer picks his secret key x from the EC Group
     * and computes his real public key y generated from x
     *
     * @return ECPoint Array where 0 is x, 1 is y
     */
    private ECPoint[] createSignersKeys() {
        ECPoint[] keys = new ECPoint[2];
        SecureRandom rnd = new SecureRandom();

        BigInteger xBigR = new BigInteger(params.getGroup().getCurve().getFieldSize(), rnd);
        ECPoint x = this.params.getGroup().getG().multiply(xBigR);
        ECPoint y = this.params.getGenerator().multiply(xBigR);

        keys[0] = x;
        keys[1] = y;

        return keys;
    }

    /**
     * @return public key of the signer
     */
    public ECPoint getY() {
        return this.y;
    }
    
    public msz.bakk.protocol.Message.Certificate registerClient(PublicKey clientPublicKey) throws NoSuchAlgorithmException, NoSuchProviderException {
        // TODO insert into Database
        int ID = this.clientList.size() + 1;
        String rawStringToSign = clientPublicKey.toString() + "," + ID;      // public key and the ID for the registered client

        this.clientList.add(clientPublicKey);

        Signature ecdsa = Signature.getInstance("SHA256withECDSA", "SunEC");
        byte[] clientCertificate = null;
        try {
            ecdsa.initSign(this.privateKey);
            ecdsa.update(rawStringToSign.getBytes(StandardCharsets.UTF_8));
            clientCertificate = ecdsa.sign();
        } catch (InvalidKeyException | SignatureException e) {
            e.printStackTrace();
        }

        return new msz.bakk.protocol.Message.Certificate(clientPublicKey, ID, clientCertificate);
    }

    public boolean verifySignature(msz.bakk.protocol.Message.Certificate certToVerify) throws SignatureException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException {
        // Verify the Signature
        Signature certificateTextSignature = Signature.getInstance("SHA256withECDSA", "SunEC");
        certificateTextSignature.initVerify(this.publicKey);
        certificateTextSignature.update(certToVerify.getBytes());

        return certificateTextSignature.verify(certToVerify.getSignature());
    }

    public void blindSign() {

    }

    public boolean verifiyReputationToken(Reputationtoken reputationtoken, String randomNumberOfHash, int rating) throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {

        // TODO verify blind signature of token

        // TODO check if random send_randomhash is not already used before

        boolean verifyHashBool;
        boolean verifyCertBool;


        PublicKey publicKeyOfCert = reputationtoken.getPubkeyFromCert();
        String reputationString = new String(reputationtoken.getBytes());

        byte[] randomHashOriginal = randomNumberOfHash.getBytes(StandardCharsets.UTF_8);
        byte[] randomHashSigToCheck = reputationtoken.getSignatureOfHash();

        // Check if the signature of the send_randomhash is correct
        Signature verifyHash = Signature.getInstance("SHA256withECDSA", "SunEC");
        verifyHash.initVerify(publicKeyOfCert);
        verifyHash.update(randomHashOriginal);
        verifyHashBool = verifyHash.verify(randomHashSigToCheck);


        byte[] certOriginal = reputationtoken.getBytesFromCert();
        byte[] certSigToCheck = reputationtoken.getSignatureFromCert();

        // Check if the certificate is correctly signed
        Signature verifyCert = Signature.getInstance("SHA256withECDSA", "SunEC");
        verifyCert.initVerify(this.publicKey);
        verifyCert.update(certOriginal);
        verifyCertBool = verifyCert.verify(certSigToCheck);

        return verifyHashBool && verifyCertBool;
    }
}
