package msz.bakk.protocol.TrustedParty;

import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;

public class Params {
    private BigInteger q;
    private X9ECParameters G;
    private ECPoint g;
    private ECPoint z;
    private ECPoint h;
    private ECPoint[] hs;

    public Params(BigInteger q, X9ECParameters G, ECPoint g, ECPoint z, ECPoint h, ECPoint[] hs) {
        // TODO HASH THEM?

        this.q = q;
        this.G = G;
        this.g = g;
        this.z = z;
        this.h = h;
        this.hs = hs;
    }

    public BigInteger getQ() {
        return q;
    }

    public X9ECParameters getGroup() {
        return G;
    }

    public ECPoint getGenerator() {
        return g;
    }

    public ECPoint getZ() {
        return z;
    }

    public ECPoint getH() {
        return h;
    }

    public ECPoint[] getHs() {
        return hs;
    }
}
