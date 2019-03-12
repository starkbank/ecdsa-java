import com.starkbank.ellipticcurve.utils.File;

import java.io.IOException;
import java.nio.file.*;

public class ReadFile {


    public static void main(String[] args)throws IOException{

        String fileName = "message.txt";
        String byteFile = "privateKey.pem";
        String byteTestFile = "signatureBinary.txt";
        File.read(fileName);
        File.read(byteFile);
        File.readBytes(byteTestFile);
        System.out.println(File.readBytes(byteTestFile).toString());
    }
}
