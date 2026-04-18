## A lightweight and fast pure Java ECDSA

### Overview

This is a pure Java implementation of the Elliptic Curve Digital Signature Algorithm (ECDSA). It is compatible with Java 8+ and OpenSSL. It uses elegant math such as Jacobian Coordinates to speed up the ECDSA on pure Java.

### Security

starkbank-ecdsa includes the following security features:

- **RFC 6979 deterministic nonces**: Eliminates the catastrophic risk of nonce reuse that leaks private keys
- **Low-S signature normalization**: Prevents signature malleability (BIP-62)
- **Public key on-curve validation**: Blocks invalid-curve attacks during verification
- **Montgomery ladder scalar multiplication**: Constant-operation point multiplication to mitigate timing side channels
- **Hash truncation**: Correctly handles hash functions larger than the curve order (e.g. SHA-512 with secp256k1)
- **Fermat's little theorem for modular inverse**: More uniform execution time than the extended Euclidean algorithm

### Installation

#### Maven Central
In pom.xml:

```xml
<dependency>
    <groupId>com.starkbank</groupId>
    <artifactId>starkbank-ecdsa</artifactId>
    <version>2.0.0</version>
</dependency>
```

Then run:
```sh
mvn clean install
```

### Curves

We currently support `secp256k1` and `prime256v1` (P-256), but you can add more curves to the project. Just use `Curve.add()`.

### Speed

We ran a test on JDK 21.0.10 on a MAC Pro. The libraries were run 100 times and the averages displayed below were obtained:

| Library            | sign          | verify  |
| ------------------ |:-------------:| -------:|
| starkbank-ecdsa    |     1.5ms     |  1.7ms  |

Performance is driven by Jacobian coordinates, a branch-balanced Montgomery ladder for variable-base scalar multiplication, a precomputed window table (2^4-ary method) for the fixed generator used in signing, curve-specific shortcuts in point doubling (A=0 for secp256k1, A=-3 for prime256v1), Shamir's trick for combined scalar multiplication during verification, and the extended Euclidean algorithm for modular inversion.

### Sample Code

How to sign a json message for [Stark Bank]:

```java
import com.starkbank.ellipticcurve.PrivateKey;
import com.starkbank.ellipticcurve.PublicKey;
import com.starkbank.ellipticcurve.Signature;
import com.starkbank.ellipticcurve.Ecdsa;


// Generate privateKey from PEM string
PrivateKey privateKey = PrivateKey.fromPem("-----BEGIN EC PRIVATE KEY-----\n...\n-----END EC PRIVATE KEY-----");

String message = "{\"transfers\": [{\"amount\": 100000000}]}";

Signature signature = Ecdsa.sign(message, privateKey);

// Generate Signature in base64
System.out.println(signature.toBase64());

// To double check if the message matches the signature:
PublicKey publicKey = privateKey.publicKey();
System.out.println(Ecdsa.verify(message, signature, publicKey));
```

Simple use:

```java
import com.starkbank.ellipticcurve.PrivateKey;
import com.starkbank.ellipticcurve.PublicKey;
import com.starkbank.ellipticcurve.Signature;
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
import com.starkbank.ellipticcurve.Curve;
import com.starkbank.ellipticcurve.PrivateKey;
import com.starkbank.ellipticcurve.PublicKey;
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

PrivateKey privateKey = new PrivateKey(newCurve, null);
PublicKey publicKey = privateKey.publicKey();
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
openssl dgst -sha256 -sign privateKey.pem -out signatureDer.txt message.txt
```

To verify, do this:

```java
import com.starkbank.ellipticcurve.Ecdsa;
import com.starkbank.ellipticcurve.PublicKey;
import com.starkbank.ellipticcurve.Signature;
import com.starkbank.ellipticcurve.utils.ByteString;
import com.starkbank.ellipticcurve.utils.File;

String publicKeyPem = File.read("publicKey.pem");
byte[] signatureBin = File.readBytes("signatureDer.txt");
String message = File.read("message.txt");

PublicKey publicKey = PublicKey.fromPem(publicKeyPem);
Signature signature = Signature.fromDer(new ByteString(signatureBin));

System.out.println(Ecdsa.verify(message, signature, publicKey));
```

You can also verify it on terminal:

```
openssl dgst -sha256 -verify publicKey.pem -signature signatureDer.txt message.txt
```

NOTE: If you want to create a Digital Signature to use with [Stark Bank], you need to convert the binary signature to base64.

```
openssl base64 -in signatureDer.txt -out signatureBase64.txt
```

You can do the same with this library:

```java
import com.starkbank.ellipticcurve.Signature;
import com.starkbank.ellipticcurve.utils.ByteString;
import com.starkbank.ellipticcurve.utils.File;

byte[] signatureBin = File.readBytes("signatureDer.txt");
Signature signature = Signature.fromDer(new ByteString(signatureBin));

System.out.println(signature.toBase64());
```

### Run unit tests

```shell
gradle test
```

### Run benchmark

```shell
gradle run
```

[Stark Bank]: https://starkbank.com
[java.security]: https://docs.oracle.com/javase/7/docs/api/index.html
