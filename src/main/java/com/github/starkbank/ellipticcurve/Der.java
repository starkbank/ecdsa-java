package com.github.starkbank.ellipticcurve;

import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import static com.github.starkbank.ellipticcurve.BinAscii.hexlify;
import static com.github.starkbank.ellipticcurve.BinAscii.unhexlify;

/**
 * Created on 05-Jan-19
 *
 * @author Taron Petrosyan
 */
public class Der {

    public static ByteString encodeSequence(ByteString... encodedPieces) {
        int totalLen = 0;
        ByteString stringPieces = new ByteString(new byte[]{0x30});
        for (ByteString p : encodedPieces) {
            totalLen += p.length();
            stringPieces.insert(p.getBytes());
        }
        stringPieces.insert(1, encodeLength(totalLen).getBytes());
        return stringPieces;
    }

    public static ByteString encodeLength(int length) {
        assert length >= 0;
        if (length < 0x80) {
            return new ByteString(new byte[]{(byte) length});
        }
        String hexString = String.format("%x", length);
        if (hexString.length() % 2 != 0) {
            hexString = "0" + hexString;
        }
        ByteString s = new ByteString(unhexlify(hexString));
        s.insert(0, new char[]{(char) (0x80 | s.length())});
        return s;

    }

    public static ByteString encodeInteger(BigInteger r) {
        assert r.compareTo(BigInteger.ZERO) >= 0;
        String h = String.format("%x", r);
        if (h.length() % 2 != 0) {
            h = "0" + h;
        }
        ByteString s = new ByteString(unhexlify(h));
        short num = s.getShort(0);
        if (num <= 0x7F) {
            s.insert(0, new char[]{0x02, (char) s.length()});
            return s;
        }
        s.insert(0, new char[]{0x02, (char) (s.length() + 1), 0x00});
        return s;
    }

    public static String encodeNumber(long n) {
        List b128Digits = new ArrayList();
        while (n != 0) {
            b128Digits.add(0, (n & 0x7f) | 0x80);
            n = n >> 7;
        }
        if (b128Digits.isEmpty()) {
            b128Digits.add(0);
        }
        int lastIndex = b128Digits.size() - 1;
        b128Digits.add(lastIndex, Integer.valueOf(b128Digits.get(lastIndex).toString()) & 0x7f);
        StringBuilder string = new StringBuilder();
        for (Object c : b128Digits) {
            string.append(c.toString());
        }
        return string.toString();
    }

    public static ByteString encodeOid(long... pieces) {
        long first = pieces[0];
        long second = pieces[1];
        assert first <= 2;
        assert second <= 39;
        ByteString body = new ByteString(new byte[]{0x06});
        for (int i = 2; i < pieces.length; i++) {
            body.insert(encodeNumber(pieces[i]).getBytes());
        }
        body.insert(1, encodeLength(body.length()).getBytes());
        body.insert(1, new char[]{(char) (40 * first + second)});
        return body;
    }

    public static ByteString encodeBitString(ByteString s) {
        s.insert(0, new byte[]{0x03});
        s.insert(1, encodeLength(s.length()).getBytes());
        return s;
    }

    public static ByteString encodeOctetString(ByteString s) {
        s.insert(0, new byte[]{0x04});
        s.insert(1, encodeLength(s.length()).getBytes());
        return s;
    }

    public static ByteString encodeConstructed(long tag, ByteString value) {
        int length = value.length();
        value.insert(0, new byte[]{(byte) (0xa0 + tag)});
        value.insert(1, encodeLength(length).getBytes());
        return value;
    }

    public static int[] readLength(ByteString string) {
        short num = string.getShort(0);
        if ((num & 0x80) == 0) {
            return new int[]{num & 0x7f, 1};
        }

        int llen = num & 0x7f;
        if (llen > string.length() - 1) {
            throw new RuntimeException("ran out of length bytes");
        }
        return new int[]{Integer.valueOf(hexlify(string.substring(1, 1 + llen)), 16), 1 + llen};
    }

    public static int[] readNumber(ByteString string) {
        int number = 0;
        int llen = 0;
        for (; ; ) {
            if (llen > string.length()) {
                throw new RuntimeException("ran out of length bytes");
            }
            number = number << 7;
            short d = string.getShort(llen);
            number += (d & 0x7f);
            llen += 1;
            if ((d & 0x80) == 0)
                break;
        }
        return new int[]{number, llen};
    }

    public static ByteString[] removeSequence(ByteString string) {
        short n = string.getShort(0);
        if (n != 0x30) {
            throw new RuntimeException(String.format("wanted sequence (0x30), got 0x%02x", n));
        }
        int[] l = readLength(string.substring(1));
        long endseq = 1 + l[0] + l[1];
        return new ByteString[]{string.substring(1 + l[1], (int) endseq), string.substring((int) endseq)};
    }

    public static Object[] removeInteger(ByteString string) {
        short n = string.getShort(0);
        if (n != 0x02) {
            throw new RuntimeException(String.format("wanted integer (0x02), got 0x%02x", n));
        }
        int[] l = readLength(string.substring(1));
        int length = l[0];
        int llen = l[1];
        ByteString numberbytes = string.substring(1 + llen, 1 + llen + length);
        ByteString rest = string.substring(1 + llen + length);
        short nbytes = numberbytes.getShort(0);
        assert nbytes < 0x80;
        return new Object[]{new BigInteger(hexlify(numberbytes), 16), rest};
    }

    public static Object[] removeObject(ByteString string) {
        int n = string.getShort(0);
        if (n != 0x06) {
            throw new RuntimeException(String.format("wanted object (0x06), got 0x%02x", n));
        }
        int[] l = readLength(string.substring(1));
        int length = l[0];
        int lengthlength = l[1];
        ByteString body = string.substring(1 + lengthlength, 1 + lengthlength + length);
        ByteString rest = string.substring(1 + lengthlength + length);
        List numbers = new ArrayList();
        while (!body.isEmpty()) {
            l = readNumber(body);
            n = l[0];
            int ll = l[1];
            numbers.add(n);
            body = body.substring(ll);
        }
        long n0 = Integer.valueOf(numbers.remove(0).toString());
        long first = n0 / 40;
        long second = n0 - (40 * first);
        numbers.add(0, first);
        numbers.add(1, second);
        long[] numbersArray = new long[numbers.size()];
        for (int i = 0; i < numbers.size(); i++) {
            numbersArray[i] = Long.valueOf(numbers.get(i).toString());
        }
        return new Object[]{numbersArray, rest};
    }

    public static ByteString[] removeBitString(ByteString string) {
        short n = string.getShort(0);
        if (n != 0x03) {
            throw new RuntimeException(String.format("wanted bitstring (0x03), got 0x%02x", n));
        }
        int[] l = readLength(string.substring(1));
        int length = l[0];
        int llen = l[1];
        ByteString body = string.substring(1 + llen, 1 + llen + length);
        ByteString rest = string.substring(1 + llen + length);
        return new ByteString[]{body, rest};
    }

    public static ByteString[] removeOctetString(ByteString string) {
        short n = string.getShort(0);
        if (n != 0x04) {
            throw new RuntimeException(String.format("wanted octetstring (0x04), got 0x%02x", n));
        }
        int[] l = readLength(string.substring(1));
        int length = l[0];
        int llen = l[1];
        ByteString body = string.substring(1 + llen, 1 + llen + length);
        ByteString rest = string.substring(1 + llen + length);
        return new ByteString[]{body, rest};
    }

    public static Object[] removeConstructed(ByteString string) {
        short s0 = string.getShort(0);
        if ((s0 & 0xe0) != 0xa0) {
            throw new RuntimeException(String.format("wanted constructed tag (0xa0-0xbf), got 0x%02x", s0));
        }
        int tag = s0 & 0x1f;
        int[] l = readLength(string.substring(1));
        int length = l[0];
        int llen = l[1];
        ByteString body = string.substring(1 + llen, 1 + llen + length);
        ByteString rest = string.substring(1 + llen + length);
        return new Object[]{tag, body, rest};
    }

    public static ByteString fromPem(String pem) {
        String[] pieces = pem.split("\n");
        StringBuilder d = new StringBuilder();
        for (String p : pieces) {
            if (!p.isEmpty() && !p.startsWith("-----")) {
                d.append(p.trim());
            }
        }
        try {
            return new ByteString(Base64.decode(d.toString()));
        } catch (IOException e) {
            throw new IllegalArgumentException("Corrupted pem string! Could not decode base64 from it");
        }
    }

    public static String toPem(ByteString der, String name) {
        String b64 = Base64.encodeBytes(der.getBytes());
        StringBuilder lines = new StringBuilder();
        lines.append(String.format("-----BEGIN %s-----\n", name));
        for (int start = 0; start < b64.length(); start += 64) {
            int end = start + 64 > b64.length() ? b64.length() : start + 64;
            lines.append(String.format("%s\n", b64.substring(start, end)));
        }
        lines.append(String.format("-----END %s-----\n", name));
        return lines.toString();
    }

}