## A lightweight and fast ECDSA

### Overview

This is a pure Java implementation of the Elliptic Curve Digital Signature Algorithm (ECDSA). It is compatible with Java 8+ and OpenSSL. It uses some elegant math such as Jacobian Coordinates to speed up the ECDSA.

### Installation

#### Maven Central
In pom.xml:

```xml
<dependency>
    <groupId>com.starkbank</groupId>
    <artifactId>starkbank-ecdsa</artifactId>
    <version>1.0.2</version>
</dependency>
```

Then run:
```sh
mvn clean install
```

### Curves

We currently support `secp256k1`, but you can add more curves to the project. You just need to use the `Curve.add()` function.

### Speed

We ran a test on JDK 13.0.1 on a MAC Air M1 2020. The libraries ran 100 times and showed the average times displayed bellow:

| Library            | sign          | verify  |
| ------------------ |:-------------:| -------:|
| [java.security]    |     0.9ms     |  2.4ms  |
| starkbank-ecdsa    |     2.5ms     |  3.7ms  |

### Sample Code

How to sign a json message for [Stark Bank]:

```java
import com.starkbank.ellipticcurve.PrivateKey;
import com.starkbank.ellipticcurve.PublicKey;
import com.starkbank.ellipticcurve.Signature;
import com.starkbank.ellipticcurve.Ecdsa;


// Generate privateKey from PEM string
PrivateKey privateKey = PrivateKey.fromPem("-----BEGIN EC PARAMETERS-----\nBgUrgQQACg==\n-----END EC PARAMETERS-----\n-----BEGIN EC PRIVATE KEY-----\nMHQCAQEEIODvZuS34wFbt0X53+P5EnSj6tMjfVK01dD1dgDH02RzoAcGBSuBBAAK\noUQDQgAE/nvHu/SQQaos9TUljQsUuKI15Zr5SabPrbwtbfT/408rkVVzq8vAisbB\nRmpeRREXj5aog/Mq8RrdYy75W9q/Ig==\n-----END EC PRIVATE KEY-----");

// Create message from json
String message = "{'transfers':[{'amount':100000000,'taxId':'594.739.480-42','name':'Daenerys Targaryen Stormborn','bankCode':'341','branchCode':'2201','accountNumber':'76543-8','tags':['daenerys','targaryen','transfer-1-external-id']}]}'";

Signature signature = Ecdsa.sign(message, privateKey);

// Generate Signature in base64. This result can be sent to Stark Bank in the request header as the Digital-Signature parameter.
System.out.println(signature.toBase64());

// To double check if the message matches the signature, do this:
PublicKey publicKey = privateKey.publicKey();

System.out.println(Ecdsa.verify(message, signature, publicKey));
```

Simple use:

```java
import com.starkbank.ellipticcurve.PrivateKey;
import com.starkbank.ellipticcurve.Ecdsa;


// Generate new Keys
PrivateKey privateKey = new PrivateKey();
PublicKey publicKey = privateKey.publicKey();

String message = "My test message";

// Generate Signature
Signature signature = Ecdsa.sign(message, privateKey);

// To verify if the signature is valid
System.out.println(Ecdsa.verify(message, signature, publicKey));

```

How to add more curves:

```java
import com.starkbank.ellipticcurve.PrivateKey;
import com.starkbank.ellipticcurve.PublicKey;
import com.starkbank.ellipticcurve.Curve;
import java.math.BigInteger;


Curve newCurve = new Curve(
    new BigInteger("f1fd178c0b3ad58f10126de8ce42435b3961adbcabc8ca6de8fcf353d86e9c00", 16),
    new BigInteger("ee353fca5428a9300d4aba754a44c00fdfec0c9ae4b1a1803075ed967b7bb73f", 16),
    new BigInteger("f1fd178c0b3ad58f10126de8ce42435b3961adbcabc8ca6de8fcf353d86e9c03", 16),
    new BigInteger("f1fd178c0b3ad58f10126de8ce42435b53dc67e140d2bf941ffdd459c6d655e1", 16),
    new BigInteger("b6b3d4c356c139eb31183d4749d423958c27d2dcaf98b70164c97a2dd98f5cff", 16),
    new BigInteger("6142e0f7c8b204911f9271f0f3ecef8c2701c307e8e4c9e183115a1554062cfb", 16),
    "frp256v1",
    new long[]{1, 2, 250, 1, 223, 101, 256, 1}
);

Curve.add(newCurve);

String publicKeyPem = "-----BEGIN PUBLIC KEY-----\nMFswFQYHKoZIzj0CAQYKKoF6AYFfZYIAAQNCAATeEFFYiQL+HmDYTf+QDmvQmWGD\ndRJPqLj11do8okvkSxq2lwB6Ct4aITMlCyg3f1msafc/ROSN/Vgj69bDhZK6\n-----END PUBLIC KEY-----";

PublicKey publicKey = PublicKey.fromPem(publicKeyPem);

System.out.println(publicKey.toPem());
```

How to generate compressed public key:

```java
import com.starkbank.ellipticcurve.PrivateKey;
import com.starkbank.ellipticcurve.PublicKey;


PrivateKey privateKey = new PrivateKey();
PublicKey publicKey = privateKey.publicKey();
String compressedPublicKey = publicKey.toCompressed();

System.out.println(compressedPublicKey);
```

How to recover a compressed public key:

```java
import com.starkbank.ellipticcurve.PrivateKey;
import com.starkbank.ellipticcurve.PublicKey;


String compressedPublicKey = "0252972572d465d016d4c501887b8df303eee3ed602c056b1eb09260dfa0da0ab2";
PublicKey publicKey = PublicKey.fromCompressed(compressedPublicKey);

System.out.println(publicKey.toPem());
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


// Read files
String publicKeyPem = Utils.readFileAsString("publicKey.pem");
byte[] signatureBin = Utils.readFileAsBytes("signature.binary");
String message = Utils.readFileAsString("message.txt");

PublicKey publicKey = PublicKey.fromPem(publicKeyPem);
Signature signature = Signature.fromDer(signatureBin);

// Get verification status:
System.out.println(Ecdsa.verify(message, signature, publicKey));
```

You can also verify it on terminal:

```
openssl dgst -sha256 -verify publicKey.pem -signature signatureBinary.txt message.txt
```

NOTE: If you want to create a Digital Signature to use in the [Stark Bank], you need to convert the binary signature to base64.

```
openssl base64 -in signatureBinary.txt -out signatureBase64.txt
```

You can also verify it with this library:

```java
import com.starkbank.ellipticcurve.utils.ByteString;
import com.starkbank.ellipticcurve.Signature;
import com.starkbank.ellipticcurve.utils.File;


// Load signature file
byte[] signatureBin = File.readBytes("signatureBinary.txt");
Signature signature = Signature.fromDer(signatureBin);
// Print signature
System.out.println(signature.toBase64());
```

[Stark Bank]: https://starkbank.com

### Run all unit tests
```shell
gradle test
```

[ecdsa-python]: https://github.com/starkbank/ecdsa-python
[java.security]: https://docs.oracle.com/javase/7/docs/api/index.html
