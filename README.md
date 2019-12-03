## A lightweight and fast ECDSA

### Overview

This is a Java fork of [ecdsa-python]

It is compatible with JDK 1.8+ and OpenSSL.
It uses some elegant math as Jacobian Coordinates to speed up the ECDSA.

### Installation

#### Maven Central
In pom.xml:

```xml
<dependency>
    <groupId>com.github.starkbank</groupId>
    <artifactId>starkbank-ecdsa</artifactId>
    <version>0.0.1-SNAPSHOT</version>
</dependency>
```

Then run:
```sh
mvn clean install
```

### Curves

We currently support `secp256k1`, but it's super easy to add more curves to the project. Just add them on `Curve.java`

### Speed

We ran a test on JDK 13.0.1 on a MAC Pro i5 2019. The libraries ran 100 times and showed the average times displayed bellow:

| Library            | sign          | verify  |
| ------------------ |:-------------:| -------:|
| [java.security]    |     0.9ms     |  2.4ms  |
| starkbank-ecdsa    |     4.3ms     |  9.9ms  |

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
        PrivateKey privateKey = new PrivateKey();
        PublicKey publicKey = privateKey.publicKey();

        String message = "Testing message";
        // Generate Signature
        Signature signature = Ecdsa.sign(message, privateKey);

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

### Run all unit tests
```shell
gradle test
```

[ecdsa-python]: https://github.com/starkbank/ecdsa-python
[java.security]: https://docs.oracle.com/javase/7/docs/api/index.html
