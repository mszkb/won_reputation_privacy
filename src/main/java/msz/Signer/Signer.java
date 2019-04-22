package msz.Signer;

import msz.ACL;
import msz.TrustedParty.Params;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.security.SecureRandom;

public class Signer implements ACL {
    private final Params params;
    private ECPoint x;
    private ECPoint y;

    public Signer(Params params) {
        this.params = params;


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
}
