import msz.TrustedParty.Params;
import msz.TrustedParty.TrustedParty;
import msz.User.Requestor;
import msz.User.Supplier;
import org.junit.Before;
import org.junit.Test;

import static junit.framework.TestCase.assertTrue;

public class WonProtocolE2ETest {


    private Requestor r;
    private Supplier s;
    private Params params;
    private msz.Signer.Signer sp;


    @Before
    public void optainACL() {

    }

    @Before
    public void createClients() {
        this.params = new TrustedParty().generateParams();
        this.r = new Requestor(this.params);
        this.s = new Supplier(this.params);
        this.sp = new msz.Signer.Signer(this.params);
    }


    @Test
    public void exchangeReputationToken() {
        // TODO create Hash User
        // TODO create Hash Supplier

        // TODO User - send cert and signature of hash to SP
        // TODO Supplier - send cert and signature of hash to SP
    }
}
