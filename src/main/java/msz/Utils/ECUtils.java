package msz.Utils;

import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.security.SecureRandom;

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
}
