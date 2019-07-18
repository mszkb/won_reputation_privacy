package msz.bakk.protocol.Utils;

import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.ECGenParameterSpec;

public class ECUtils {
    /**
     * Generates a random point on the given elliptic Curve
     *
     * @param g ... Generator of the Elliptic Curve Group
     * @param fieldSize ... Size of the Group
     * @return random point on given elliptic Curve Group
     */
    public static ECPoint createRandomPoint(ECPoint g, int fieldSize) {
        SecureRandom rnd = new SecureRandom();
        BigInteger zBigR = new BigInteger(fieldSize, rnd);
        return g.multiply(zBigR);
    }

    /**
     * Generates a random point on the given elliptic Curve
     *
     * @param EC ... Parameters of the elliptic curve
     * @return random point on given elliptic Curve Group
     */
    public static ECPoint createRandomPoint(X9ECParameters EC) {
        SecureRandom rnd = new SecureRandom();
        BigInteger zBigR = new BigInteger(EC.getCurve().getFieldSize(), rnd);
        return EC.getG().multiply(zBigR);
    }

    public static String hashMessage(String s) {
        MessageDigest digest = null;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        byte[] hash = digest.digest(s.getBytes(StandardCharsets.UTF_8));
        return new String(Hex.encode(hash));
    }

    /**
     * Generates a key pair (private, public key) with a predefined algorithm
     *
     * @return
     * @throws InvalidAlgorithmParameterException
     * @throws NoSuchProviderException
     * @throws NoSuchAlgorithmException
     */
    public static KeyPair generateKeyPair() {
        KeyPairGenerator kpg = null;
        KeyPair kp = null;

        try {
            kpg = KeyPairGenerator.getInstance("EC", "SunEC");
            ECGenParameterSpec ecsp = new ECGenParameterSpec("secp384r1");
            kpg.initialize(ecsp);

            kp = kpg.generateKeyPair();
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException | NoSuchProviderException e) {
            e.printStackTrace();
        }

        return kp;
    }
}
