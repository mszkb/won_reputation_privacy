package msz.Signer;

import msz.ACL;
import msz.TrustedParty.Params;
import msz.Utils.ECUtils;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.ArrayList;

public class Signer implements ACL {
    private final Params params;
    private ECPoint x;
    private ECPoint y;

    private final PrivateKey privateKey;
    private final PublicKey publicKey;

    private ArrayList<PublicKey> clientList = new ArrayList<>();

    public Signer(Params params) {
        this.params = params;

        // Signer Keys
        KeyPair signerKP = null;
        try { signerKP = ECUtils.generateKeyPair();
        } catch (InvalidAlgorithmParameterException | NoSuchProviderException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        if(signerKP == null) {
            throw new NullPointerException("KeyPair generation Failed");
        }

        this.privateKey = signerKP.getPrivate();
        this.publicKey = signerKP.getPublic();
    }

    private void generateKeys() {


    }

    public void setup() {
        // msz.Signer picks his secret key x and compute real public key y
        // the secret key is not a ssh key or somewhat, just a random point on the curve
        ECPoint[] keys = createSignersKeys();
        this.x = keys[0];
        this.y = keys[1];
    }

    public void registration() {

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
    
    public Certificate registerClient() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
        // TODO insert into Database
        int ID = this.clientList.size() + 1;
        PublicKey clientPublicKey = ECUtils.generateKeyPair().getPublic();  // only pubkey for client
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

        return new Certificate(clientPublicKey, ID, clientCertificate);
    }

    public boolean verifySignature(Certificate certToVerify) throws SignatureException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException {
        // Verify the Signature
        Signature certificateTextSignature = Signature.getInstance("SHA256withECDSA", "SunEC");
        certificateTextSignature.initVerify(this.publicKey);
        certificateTextSignature.update(certToVerify.getBytes());

        return certificateTextSignature.verify(certToVerify.getSignature());
    }
}
