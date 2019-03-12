import com.starkbank.ellipticcurve.Ecdsa;
import com.starkbank.ellipticcurve.PublicKey;
import com.starkbank.ellipticcurve.Signature;
import com.starkbank.ellipticcurve.utils.ByteString;
import com.starkbank.ellipticcurve.utils.File;

public class VerifyKeys {


    public static void main(String[] args){
        // Read files
        String publicKeyPem = File.read("publicKey.pem");
        byte[] signatureBin = File.readBytes("signatureBinary.txt");
        String message = File.read("message.txt");

        ByteString byteString = new ByteString(signatureBin);

        PublicKey publicKey = PublicKey.fromPem(publicKeyPem);
        Signature signature = Signature.fromDer(byteString);

        // Get verification status:
        boolean verified = Ecdsa.verify(message, signature, publicKey);
        System.out.println("Verification status: " + verified);
    }
}
