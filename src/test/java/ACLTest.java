import SocketTest.TestBase;
import msz.Message.Message;
import msz.Message.Reputationtoken;
import msz.Signer.Signer;
import msz.User.Requestor;
import msz.TrustedParty.Params;
import msz.TrustedParty.TrustedParty;
import org.junit.Before;
import org.junit.Test;

import java.math.BigInteger;
import java.security.spec.ECPoint;
import java.sql.Timestamp;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.List;

import static junit.framework.TestCase.assertEquals;
import static org.hamcrest.MatcherAssert.assertThat;

public class ACLTest extends TestBase {

    private Params params;
    private Signer signer;

    private List<String> attributes;

    @Before
    public void setup() {
        attributes = new ArrayList<>();
        attributes.add("msz");
        attributes.add("mszkb@skca.eu");

        this.params = new TrustedParty(attributes.size()).generateParams();
        this.signer = new Signer(this.params);

        assertEquals(this.params.getHs().length, attributes.size());
    }

    @Test
    public void registerTest() {
        Requestor r = new Requestor(this.params);

        System.out.println(r.createCommitment(4.3f));
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
