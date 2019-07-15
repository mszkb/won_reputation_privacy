package msz.bakk.cmd;

import msz.bakk.protocol.Message.Certificate;
import msz.bakk.protocol.Message.Reputationtoken;
import msz.bakk.protocol.Utils.MessageUtils;
import msz.bakk.protocol.Utils.WonRepRdfUtils;
import msz.bakk.protocol.vocabulary.REP;
import org.apache.jena.rdf.model.Model;
import org.apache.jena.rdf.model.ModelFactory;
import org.apache.jena.rdf.model.Resource;
import won.protocol.message.WonMessage;
import won.protocol.message.WonMessageBuilder;
import won.protocol.util.RdfUtils;

import java.net.URI;
import java.security.NoSuchAlgorithmException;

public class RDFMessages {

    public static WonMessage createWonMessage(Model m) {
        return WonMessageBuilder.setMessagePropertiesForConnectionMessage(
                URI.create("messageUri"),
                URI.create("localConnection"),
                URI.create("localAtom"),
                URI.create("localWonNode"),
                URI.create("targetConnection"),
                URI.create("TargetAtom"),
                URI.create("remoteWonNode"),
                m).build();
    }

    public static Model generateRandomHash() {

        String randomHash = "";
        try {
            randomHash = Utils.generateRandomHash();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        return generateRandomHash(randomHash);
    }

    public static Model generateRandomHash(String hash) {
        Model model = WonRepRdfUtils.createBaseModel();
        Resource baseRes = RdfUtils.findOrCreateBaseResource(model);
        baseRes.addProperty(REP.RANDOM_HASH, hash);

        return model;
    }

    public static Model createReputationToken(String signedHash, Certificate cert) {
        // TODO Public key wie im WoN

        // provided random send_randomhash
        // new random send_randomhash
        Model model = WonRepRdfUtils.createBaseModel();
        Resource baseRes = RdfUtils.findOrCreateBaseResource(model);
        Resource certificate = model.createResource();
        certificate.addProperty(REP.USER_ID, String.valueOf(cert.getID()));
        certificate.addProperty(REP.PUBLIC_KEY, cert.getPublicKey().toString());
        Resource reputationToken = model.createResource();
        reputationToken.addProperty(REP.CERTIFICATE, certificate);
        // TODO built in property exists?
        reputationToken.addProperty(REP.SIGNED_RANDOM_HASH, signedHash);
        baseRes.addProperty(REP.REPUTATIONTOKEN, reputationToken);

        return model;
    }

    public static Model blindAnswer(Reputationtoken RT, String blindSignature) {
        Model model = WonRepRdfUtils.createBaseModel();
        Resource baseRes = RdfUtils.findOrCreateBaseResource(model);
        Resource certificate = model.createResource();
        certificate.addProperty(REP.USER_ID, String.valueOf(RT.getCertificate().getID()));
        certificate.addProperty(REP.PUBLIC_KEY, RT.getCertificate().getPublicKey().toString());
        Resource reputationToken = model.createResource();
        reputationToken.addProperty(REP.CERTIFICATE, certificate);
        // TODO built in property exists?
        reputationToken.addProperty(REP.SIGNED_RANDOM_HASH, MessageUtils.encodeBytes(RT.getSignatureOfHash()));
        baseRes.addProperty(REP.REPUTATIONTOKEN, reputationToken);
        baseRes.addProperty(REP.BLIND_SIGNED_REPUTATIONTOKEN, blindSignature);

        return model;
    }

    public static Model rate(float rating, String message, Reputationtoken RT, String blindSignature, String originalHash) {
        Model model = WonRepRdfUtils.createBaseModel();
        Resource baseRes = RdfUtils.findOrCreateBaseResource(model);
        Resource certificate = model.createResource();
        certificate.addProperty(REP.USER_ID, String.valueOf(RT.getCertificate().getID()));
        certificate.addProperty(REP.PUBLIC_KEY, RT.getCertificate().getPublicKey().toString());
        Resource reputationToken = model.createResource();
        reputationToken.addProperty(REP.CERTIFICATE, certificate);
        // TODO built in property exists?
        reputationToken.addProperty(REP.SIGNED_RANDOM_HASH, MessageUtils.encodeBytes(RT.getSignatureOfHash()));
        baseRes.addProperty(REP.REPUTATIONTOKEN, reputationToken);
        baseRes.addProperty(REP.BLIND_SIGNED_REPUTATIONTOKEN, blindSignature);
        baseRes.addProperty(REP.RATING, String.valueOf(rating));
        baseRes.addProperty(REP.RATING_COMMENT, message);
        baseRes.addProperty(REP.RANDOM_HASH, originalHash);

        return model;
    }
}
