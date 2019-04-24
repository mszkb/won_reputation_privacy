package msz.Message;

import msz.Utils.ECUtils;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.math.ec.ECPoint;

/**
 * Signature to be signed
 */
public class Signature {
    private int attributeLength;  // how much attributes
    private final ECPoint R;      // randomness

    public Signature(String[] messageToBeSigned, X9ECParameters EC) {
        this.R = ECUtils.createRandomPoint(EC);
        this.attributeLength = messageToBeSigned.length;
    }

    public int getAttributeLength() {
        return attributeLength;
    }
}
