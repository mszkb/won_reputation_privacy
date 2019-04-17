package msz;

import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;

public class ECTest {
    public static void main(String[] args) {
        X9ECParameters x9A = ECNamedCurveTable.getByName("secp192r1");
    }
}
