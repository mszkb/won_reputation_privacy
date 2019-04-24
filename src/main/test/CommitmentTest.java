import msz.Signer.Signer;
import msz.TrustedParty.Params;
import msz.TrustedParty.TrustedParty;
import msz.Utils.ECUtils;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.Before;
import org.junit.Test;

import java.io.UnsupportedEncodingException;

public class CommitmentTest {

    private Params params;
    private Signer signer;

    @Before
    public void setup() {
        this.params = new TrustedParty().generateParams();
        this.signer = new Signer(this.params);
    }

    @Test
    public void test_PedersenCommitment() throws UnsupportedEncodingException {
        // https://files.zotero.net/12620611427/From%20Zero%20Knowledge%20Proofs%20to%20Bulletproofs%20Paper%20.pdf

        // C = rH + (v1*G1 + v2*G2 + ... + vn * Gn) = rH + vG

        // rH
        ECPoint rH = ECUtils.createRandomPoint(this.params.getGroup());

        // v1*G1 + ... + vn*Gn
        // Gx ... Hash of the point -> H(encode(G)||i)
        // vx ... value which should be hided
//        byte[] v1 = "Martin Szalay".getBytes("UTF-8");
//        byte[] v2 = "25".getBytes("UTF-8");
//        byte[] v3 = "TU Wien".getBytes("UTF-8");
//        byte[] v4 = "Bla".getBytes("UTF-8");
//        byte[] v5 = "Blub".getBytes("UTF-8");
//        byte[][] vs = new byte[][]{v1, v2, v3, v4, v5};

        System.out.println(ECUtils.hashMessage("Martin Szalay"));
//        this.params.getGenerator().

//        byte result = rH.getEncoded(false);
//
//        for(int i = 1; i <= this.params.getHs().length; i++) {
//            int G = this.params.getHs()[i].hashCode();
//            result += (byte) (G * vs[i]);
//        }

//        System.out.println(v1);
    }
}
