import msz.Signer.BlindSignature;
import msz.Signer.Signer;
import msz.TrustedParty.Params;
import msz.TrustedParty.TrustedParty;
import msz.User.Requestor;
import msz.User.Supplier;
import msz.Utils.RSAUtils;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;

public class BlindSignatureTest {

    private Params params;
    private Requestor r;
    private Supplier s;
    private Signer sp;

    @Before
    public void createClients() {
        this.params = new TrustedParty().generateParams();
        this.r = new Requestor(this.params);
        this.s = new Supplier(this.params);
        this.sp = new Signer(this.params);
    }

    @Test
    public void test_blindSignature() {
        BlindSignature blindSigner = new BlindSignature();

        byte[] message = "My BLIND MESSAGE".getBytes(StandardCharsets.UTF_8);

        byte[] blindedSignature = blindSigner.blindAndSign(message);
        Assert.assertTrue(blindSigner.verify(message, blindedSignature));
    }
}
