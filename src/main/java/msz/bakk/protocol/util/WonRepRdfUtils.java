package msz.bakk.protocol.util;

import org.apache.jena.rdf.model.Model;
import org.apache.jena.rdf.model.ModelFactory;
import org.slf4j.LoggerFactory;
import won.protocol.util.WonRdfUtils;

import java.util.logging.Logger;

public class WonRepRdfUtils extends WonRdfUtils {
    private static final Logger logger = (Logger) LoggerFactory.getLogger(WonRepRdfUtils.class);

    public static Model addStuff(Model model) {
        // Model messageModel = createModelWithBaseResource();
        // Resource baseRes =
        // messageModel.createResource(messageModel.getNsPrefixURI(""));
        // baseRes.addProperty(WONCON.text, message, XSDDatatype.XSDstring);
        // return messageModel;
        return null;
    }

    public static Model createBaseModel() {
        return createModelWithBaseResource();
    }

    private static Model createModelWithBaseResource() {
        Model model = ModelFactory.createDefaultModel();
        model.setNsPrefix("", "no:uri");
        model.createResource(model.getNsPrefixURI(""));
        return model;
    }
}
