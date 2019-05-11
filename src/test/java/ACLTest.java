import msz.Message.Message;
import msz.Message.Reputationtoken;
import msz.Signer.Signer;
import msz.User.Requestor;
import msz.TrustedParty.Params;
import msz.TrustedParty.TrustedParty;
import org.junit.Before;
import org.junit.Test;

public class ACLTest {

    private Params params;
    private Signer signer;

    @Before
    public void setup() {
        this.params = new TrustedParty().generateParams();
        this.signer = new Signer(this.params);
    }

    @Test
    public void registerTest() {
//        Message m = new Reputationtoken(certificate, signatureOfHash);
//        String[] attributes = new String[]{"SECRET KEY", "REPUTATION", "EXPIRATION"};
//        Requestor r = new Requestor(this.params, this.signer.getY(), m, attributes);
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
