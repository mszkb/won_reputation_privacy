import SocketTest.TestBase;
import msz.Signer.Signer;
import msz.TrustedParty.Params;
import msz.TrustedParty.TrustedParty;
import msz.User.Requestor;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.Before;
import org.junit.Test;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.ArrayList;
import java.util.List;

import static junit.framework.TestCase.assertEquals;

public class ACLTest extends TestBase {

    private Params params;
    private Signer signer;

    private List<String> attributes;

    @Before
    public void setup() throws NoSuchAlgorithmException {
        attributes = new ArrayList<>();
        attributes.add("msz");
        attributes.add("mszkb@skca.eu");

        this.params = new TrustedParty(attributes.size()).generateParams();
        this.signer = new Signer(this.params);

        assertEquals(this.params.getHs().length, attributes.size());
    }

    @Test
    public void registerTest() throws NoSuchProviderException {
        Requestor r = new Requestor(this.params);


        System.out.println(r.createCommitment(4.3f));

        ECPoint commitment = r.createCommitment(4.3f);
        this.signer.registration(commitment);
        this.signer.preparation();
    }

    @Test
    public void preperationTest() {

    }

    @Test
    public void validationTest() {

    }

    @Test
    public void verificationTest() {

    }

    @Test
    public void testProtocol() {

    }

    @Test
    public void testFullImplementation() {

    }


}
