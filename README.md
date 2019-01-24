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
// Generate Keys
PrivateKey privateKey = new PrivateKey();
PublicKey publicKey = privateKey.publicKey();

String message = "My test message";

// Generate Signature
Signature signature = Ecsda.sign(message, privateKey);

//  Verify if signature is valid
System.out.println(Ecsda.verify(message, signature, publicKey));
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
String publicKeyPem = new String(Files.readAllBytes(Path.get("publicKey.pem")));
byte[] signatureBin = Files.readAllBytes(Path.get("signatureBinary.txt"));
String message = new String(Files.readAllBytes(Path.get("message.txt")));

PublicKey publicKey = PublicKey.fromPem(publicKeyPem);
Signature signature = Signature.fromDer(signatureBin);

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

With this library, you can do it:

```java
byte[] signatureBin = Files.readAllBytes(Path.get("signatureBinary.txt"));

Signature signature = Signature.fromDer(new ByteString(signatureBin));

System.out.println(signature.toBase64());
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
gradle test