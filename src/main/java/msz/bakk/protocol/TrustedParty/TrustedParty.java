package msz.bakk.protocol.TrustedParty;

import msz.bakk.protocol.Utils.ECUtils;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;

public class TrustedParty {

    private String G_name = "secp192r1";
    private int maxAttributes = 5;

    public TrustedParty() {
    }

    public TrustedParty(int maxAttributes) {
        this.maxAttributes = maxAttributes;
    }

    public Params generateParams() {
        // TODO send_randomhash the points


        // do not use java.security
        // bouncycastle offers built in function

        // Create G, g
        X9ECParameters EC = ECNamedCurveTable.getByName(G_name);    // G our group is named
        ECPoint g = EC.getG();  // g
                                // bouncycastle does not provide a good documentation
                                // looking into the source - getGroup() returns this.g and that is
                                // an ECPoint. g is a generator that means:
                                // a random point on the curve from which further points are created

        // Create q
        BigInteger q = EC.getCurve().getOrder();

        // Create z, h, h1, h2, h3, ..., hn
        ECPoint z = ECUtils.createRandomPoint(EC);
        ECPoint h = ECUtils.createRandomPoint(EC);
        ECPoint[] hs = new ECPoint[this.maxAttributes];

        // create random points for each attribute @see this.maxAttributes
        for(int i = 0; i < this.maxAttributes; i++) {
            hs[i] = ECUtils.createRandomPoint(EC);
        }

        return new Params(q, EC, g, z, h, hs);
    }
}
