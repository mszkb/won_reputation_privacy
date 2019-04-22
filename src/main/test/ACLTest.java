import msz.TrustedParty.Params;
import msz.TrustedParty.TrustedParty;
import org.junit.Test;

public class ACLTest {

    @Test
    public void setupTest() {
        Params params = new TrustedParty().generateParams();
    }
}
