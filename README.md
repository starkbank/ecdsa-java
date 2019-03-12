## A lightweight and fast ECDSA

### Overview

This is a Java fork of [ecdsa-python]


[ecdsa-python]: https://github.com/starkbank/ecdsa-python

It is compatible with OpenSSL and is fast.
It uses some elegant math as Jacobian Coordinates to speed up the ECDSA.

### Curves

We currently support `secp256k1`, but it's super easy to add more curves to the project. Just add them on `Curve.java`

### Sample Code

How to use it:

```java
import com.starkbank.ellipticcurve.PrivateKey;
import com.starkbank.ellipticcurve.PublicKey;
import com.starkbank.ellipticcurve.Signature;
import com.starkbank.ellipticcurve.Ecdsa;

public class GenerateKeys{


    public static void main(String[] args){
        // Generate Keys
        PrivateKey pvtKey = new PrivateKey();
        PublicKey publicKey = pvtKey.publicKey();

        String message = "Testing message";
        // Generate Signature
        Signature signature = Ecdsa.sign(message, pvtKey);

        // Verify if signature is valid
        boolean verified = Ecdsa.verify(message, signature, publicKey) ;

        // Return the signature verification status
        System.out.println("Verified: " + verified);

    }
}
```
### OpenSSL

This library is compatible with OpenSSL, so you can use it to generate keys:

```
openssl ecparam -name secp256k1 -genkey -out privateKey.pem
openssl ec -in privateKey.pem -pubout -out publicKey.pem
```

Create a message.txt file and sign it:

```
openssl dgst -sha256 -sign privateKey.pem -out signatureBinary.txt message.txt
```

It's time to verify:

```java
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
```

You can also verify it on terminal:

```
openssl dgst -sha256 -verify publicKey.pem -signature signatureBinary.txt message.txt
```

NOTE: If you want to create a Digital Signature to use in the [Stark Bank], you need to convert the binary signature to base64.

```
openssl base64 -in signatureBinary.txt -out signatureBase64.txt
```

With this library, you can do it:

```java
import com.starkbank.ellipticcurve.utils.ByteString;
import com.starkbank.ellipticcurve.Signature;
import com.starkbank.ellipticcurve.utils.File;

public class GenerateSignature {


    public static void main(String[] args) {
        // Load signature file
        byte[] signaturteBin = File.readBytes("signatureBinary.txt");
        Signature signature = Signature.fromDer(new ByteString(signaturteBin));
        // Print signature
        System.out.println(signature.toBase64());
        }
}
```

[Stark Bank]: https://starkbank.com

### How to install

#### Maven Central
```xml
<dependency>
    <groupId>com.github.starkbank</groupId>
    <artifactId>ecdsa-java</artifactId>
    <version>0.0.1-SNAPSHOT</version>
</dependency>
```

### Run all unit tests
```shell
gradle test
```
