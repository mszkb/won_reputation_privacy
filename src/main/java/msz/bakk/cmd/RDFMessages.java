package msz.bakk.cmd;

import msz.bakk.protocol.Message.Certificate;
import msz.bakk.protocol.Message.Reputationtoken;
import msz.bakk.protocol.Utils.MessageUtils;
import org.apache.jena.rdf.model.Model;
import org.apache.jena.rdf.model.Resource;
import won.protocol.message.WonMessage;
import won.protocol.message.WonMessageBuilder;
import won.protocol.util.WonRepRdfUtils;
import won.protocol.vocabulary.REP;

import java.net.URI;
import java.security.NoSuchAlgorithmException;

public class RDFMessages {

    public static WonMessage generateRandomHash() {

        String randomHash = "";
        try {
            randomHash = Utils.generateRandomHash();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        Model model = WonRepRdfUtils.createBaseModel();
        Resource baseRes = model.createResource();
        baseRes.addProperty(REP.RANDOM_HASH, randomHash);
        final WonMessage msg = WonMessageBuilder.setMessagePropertiesForConnectionMessage(
                URI.create("messageUri"),
                URI.create("localConnection"),
                URI.create("localAtom"),
                URI.create("localWonNode"),
                URI.create("targetConnection"),
                URI.create("TargetAtom"),
                URI.create("remoteWonNode"),
                model).build();

        return msg;
    }

    public static WonMessage createReputationToken() {
        String randomHash = "";
        try {
            randomHash = Utils.generateRandomHash();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        // new random hash
        Model model = WonRepRdfUtils.createBaseModel();
        Resource baseRes = model.createResource();
        Resource certificate = model.createResource();
        certificate.addProperty(REP.USER_ID, "1");
        certificate.addProperty(REP.PUBLIC_KEY, "6lLkr3HbnfuOhGKzEuydFgWZIiWTtXdLKKsXIftYg7E=");
        Resource reputationToken = model.createResource();
        reputationToken.addProperty(REP.CERTIFICATE, certificate);
        // TODO built in property exists?
        reputationToken.addProperty(REP.SIGNED_RANDOM_HASH,
                "eA0Aum8jgAkHoECTgn6T1ZqjOoE9rbxG9vJDzhnt9dIfp7W7rNBdWbQg/JWXjbGVUmXZTUHm9BhqmVMstma+iSUDsOkdKt+cnYQ8ctt7jcEAhENxJgsL1GmTA07hSunHpD+yTuPVNZyTuKHe47q0hJOvFiKcYN2boEA3iU3uwJA=");
        baseRes.addProperty(REP.REPUTATIONTOKEN, reputationToken);
        final WonMessage msg = WonMessageBuilder.setMessagePropertiesForConnectionMessage(
                URI.create("messageUri"),
                URI.create("localConnection"),
                URI.create("localAtom"),
                URI.create("localWonNode"),
                URI.create("targetConnection"),
                URI.create("TargetAtom"),
                URI.create("remoteWonNode"),
                model).build();

        System.out.println("This is a stub implementation - this token is valid but always the same");
        return msg;
    }

    public static WonMessage createReputationToken(String signedHash, Certificate cert) {
        // provided random hash
        // new random hash
        Model model = WonRepRdfUtils.createBaseModel();
        Resource baseRes = model.createResource();
        Resource certificate = model.createResource();
        certificate.addProperty(REP.USER_ID, String.valueOf(cert.getID()));
        certificate.addProperty(REP.PUBLIC_KEY, cert.getPublicKey().toString());
        Resource reputationToken = model.createResource();
        reputationToken.addProperty(REP.CERTIFICATE, certificate);
        // TODO built in property exists?
        reputationToken.addProperty(REP.SIGNED_RANDOM_HASH, signedHash);
        baseRes.addProperty(REP.REPUTATIONTOKEN, reputationToken);
        final WonMessage msg = WonMessageBuilder.setMessagePropertiesForConnectionMessage(
                URI.create("messageUri"),
                URI.create("localConnection"),
                URI.create("localAtom"),
                URI.create("localWonNode"),
                URI.create("targetConnection"),
                URI.create("TargetAtom"),
                URI.create("remoteWonNode"),
                model).build();

        return msg;
    }

    public static WonMessage blindAnswer(Reputationtoken RT, String blindSignature) {
        Model model = WonRepRdfUtils.createBaseModel();
        Resource baseRes = model.createResource();
        Resource certificate = model.createResource();
        certificate.addProperty(REP.USER_ID, String.valueOf(RT.getCertificate().getID()));
        certificate.addProperty(REP.PUBLIC_KEY, RT.getCertificate().getPublicKey().toString());
        Resource reputationToken = model.createResource();
        reputationToken.addProperty(REP.CERTIFICATE, certificate);
        // TODO built in property exists?
        reputationToken.addProperty(REP.SIGNED_RANDOM_HASH, MessageUtils.encodeBytes(RT.getSignatureOfHash()));
        baseRes.addProperty(REP.REPUTATIONTOKEN, reputationToken);
        baseRes.addProperty(REP.BLIND_SIGNED_REPUTATIONTOKEN, blindSignature);
        final WonMessage msg = WonMessageBuilder.setMessagePropertiesForConnectionMessage(
                URI.create("messageUri"),
                URI.create("localConnection"),
                URI.create("localAtom"),
                URI.create("localWonNode"),
                URI.create("targetConnection"),
                URI.create("TargetAtom"),
                URI.create("remoteWonNode"),
                model).build();

        return msg;
    }

    public static WonMessage rate(float rating, String message, Reputationtoken RT, String blindSignature, String originalHash) {
        Model model = WonRepRdfUtils.createBaseModel();
        Resource baseRes = model.createResource();
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
        final WonMessage msg = WonMessageBuilder.setMessagePropertiesForConnectionMessage(
                URI.create("messageUri"),
                URI.create("localConnection"),
                URI.create("localAtom"),
                URI.create("localWonNode"),
                URI.create("targetConnection"),
                URI.create("TargetAtom"),
                URI.create("remoteWonNode"),
                model).build();

        return msg;
    }
}
