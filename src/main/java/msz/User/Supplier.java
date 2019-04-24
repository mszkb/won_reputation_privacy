package msz.User;

import msz.ACL;
import msz.Signer.Certificate;
import msz.Signer.Signer;
import msz.TrustedParty.Params;
import msz.WonProtocol;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;


public class Supplier implements ACL, WonProtocol {

    private Params params;
    private Certificate certificate;

    public Supplier() {

    }

    public Supplier(Params params) {
        this.params = params;
    }

    public void setup() {

    }

    public void registration() {

    }

    public void preparation() {

    }

    public void validation() {

    }

    public void verifiction() {

    }

    @Override
    public void registerWithSystem() {

    }

    public Certificate registerWithSystem(Signer sp) {
        try {
            this.certificate = sp.registerClient();
            return this.certificate;
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }
        return null;
    }

    @Override
    public Certificate getCertificate() {
        return this.certificate;
    }
}
