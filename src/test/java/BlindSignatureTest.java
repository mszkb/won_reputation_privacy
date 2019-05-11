import msz.Signer.BlindSignature;
import msz.Signer.Signer;
import msz.TrustedParty.Params;
import msz.TrustedParty.TrustedParty;
import msz.User.Requestor;
import msz.User.Supplier;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.nio.charset.StandardCharsets;

public class BlindSignatureTest {

    private Params params;
    private Requestor r;
    private Supplier s;
    private Signer sp;
    private BlindSignature blindSigner;

    @Before
    public void createClients() {
        this.params = new TrustedParty().generateParams();
        this.r = new Requestor(this.params);
        this.s = new Supplier(this.params);
        this.sp = new Signer(this.params);

        this.blindSigner = new BlindSignature();
    }

    @Test
    public void test_blindSignature() {
        byte[] message = "My BLIND MESSAGE".getBytes(StandardCharsets.UTF_8);
        byte[] blindedSignature = this.blindSigner.blindAndSign(message);
        Assert.assertTrue(this.blindSigner.verify(message, blindedSignature));
    }
}
