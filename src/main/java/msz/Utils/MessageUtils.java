package msz.Utils;

import msz.Message.Reputationtoken;

import java.io.*;
import java.util.Base64;

public class MessageUtils {

    // @source: https://stackoverflow.com/a/134918
    // @from: OscarRyz
    // @site: stackoverflow

    /** Read the object from Base64 string. */
    public static Object fromString( String s ) throws IOException,
            ClassNotFoundException {
        byte [] data = Base64.getDecoder().decode( s );
        ObjectInputStream ois = new ObjectInputStream(
                new ByteArrayInputStream(  data ) );
        Object o  = ois.readObject();
        ois.close();
        return o;
    }

    /** Write the object to a Base64 string. */
    public static String toString( Serializable o ) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream( baos );
        oos.writeObject( o );
        oos.close();
        return Base64.getEncoder().encodeToString(baos.toByteArray());
    }

    /** Use this method for encoding bytes[] like blind signatures **/
    public static String encodeBytes(byte[] toEncode) {
        return Base64.getEncoder().encodeToString(toEncode);
    }
    public static byte[] decodeToBytes(String toDecode) {
        return Base64.getDecoder().decode(toDecode);
    }

    public static Reputationtoken decodeRT(String base64encodedRT) {
        try {
            return (Reputationtoken) MessageUtils.fromString(base64encodedRT);
        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
        }

        return null;
    }
}
