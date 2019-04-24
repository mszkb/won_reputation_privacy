package msz;

import msz.Signer.Certificate;

public interface WonProtocol {
    void registerWithSystem();
    Certificate getCertificate();
}
