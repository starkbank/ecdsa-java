package com.github.starkbank.ellipticcurve;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import static com.github.starkbank.ellipticcurve.BinAscii.*;

/**
 * Created on 05-Jan-19
 *
 * @author Taron Petrosyan
 */
public class Der {

    public static String encodeSequence(String... encodedPieces) {
        int totalLen = 0;
        StringBuilder stringPieces = new StringBuilder();
        for (String p : encodedPieces) {
            totalLen += p.length();
            stringPieces.append(p);
        }
        return ((char) 0x30) + encodeLength(totalLen) + stringPieces;
    }

    public static String encodeLength(long length) {
        assert length >= 0;
        if (length < 0x80) {
            return String.valueOf((char) length);
        }
        String s = String.format("%x", length);
        if (s.length() % 2 != 0) {
            s = "0" + s;
        }
        s = unhexlify(s);
        return ((char) (0x80 | s.length()) + s);

    }

    public static String encodeInteger(long r) {
        assert r >= 0;
        String h = String.format("%x", r);
        if (h.length() % 2 != 0) {
            h = "0" + h;
        }
        String s = unhexlify(h);
        char num = s.charAt(0);
        if (num <= 0x7F) {
            return (char) (0x02) + (char) (s.length()) + s;
        }

        return (char) (0x02) + (char) (s.length() + 1) + ((char) 0x00) + s;
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

    public static String encodeOid(long... pieces) {
        long first = pieces[0];
        long second = pieces[1];
        assert first <= 2;
        assert second <= 39;
        StringBuilder body = new StringBuilder();
        body.append((char) (40 * first + second));
        for (int i = 2; i < pieces.length; i++) {
            body.append(encodeNumber(pieces[i]));
        }
        return (char) 0x06 + encodeLength(body.length()) + body;
    }

    public static String encodeBitString(String s) {
        return (char) 0x03 + encodeLength(s.length()) + s;
    }

    public static String encodeOctetString(String s) {
        return (char) 0x04 + encodeLength(s.length()) + s;
    }

    public static String encodeConstructed(long tag, String value) {
        return (char) (0xa0 + tag) + encodeLength(value.length()) + value;
    }

    public static long[] readLength(String string) {
        char num = string.charAt(0);
        if ((num & 0x80) != 0) {
            return new long[]{num & 0x7f, 1};
        }

        int llen = num & 0x7f;
        if (llen > string.length() - 1) {
            throw new RuntimeException("ran out of length bytes");
        }
        return new long[]{Long.valueOf(hexlify(string.substring(1, 1 + llen)), 16), 1 + llen};
    }

    public static long[] readNumber(String string) {
        long number = 0;
        int llen = 0;
        for (; ; ) {
            if (llen > string.length()) {
                throw new RuntimeException("ran out of length bytes");
            }
            number = number << 7;
            char d = string.charAt(llen);
            number += (d & 0x7f);
            llen += 1;
            if ((d & 0x80) != 0)
                break;
        }
        return new long[]{number, llen};
    }

    public static String[] removeSequence(String string) {
        if (string.charAt(0) != 0x30) {
            char n = string.charAt(0);
            throw new RuntimeException(String.format("wanted sequence (0x30), got 0x%02x", (long) n));
        }
        long[] l = readLength(string.substring(1));
        long endseq = 1 + l[0] + l[1];
        return new String[]{string.substring(1 + (int) l[1], (int) endseq), string.substring((int) endseq)};
    }

    public static Object[] removeInteger(String string) {
        if (string.charAt(0) != 0x02) {
            char n = string.charAt(0);
            throw new RuntimeException(String.format("wanted integer (0x02), got 0x%02x", (long) n));
        }
        long[] l = readLength(string.substring(1));
        int length = (int) l[0];
        int llen = (int) l[1];
        String numberbytes = string.substring(1 + llen, 1 + llen + length);
        String rest = string.substring(1 + llen + length);
        char nbytes = numberbytes.charAt(0);
        assert nbytes < 0x80;
        return new Object[]{Long.valueOf(hexlify(numberbytes), 16), rest};
    }

    public static Object[] removeObject(String string) {
        if (string.charAt(0) != 0x06) {
            char n = string.charAt(0);
            throw new RuntimeException(String.format("wanted object (0x06), got 0x%02x", (long) n));
        }
        long[] l = readLength(string.substring(1));
        int length = (int) l[0];
        int lengthlength = (int) l[1];
        String body = string.substring(1 + lengthlength, 1 + lengthlength + length);
        String rest = string.substring(1 + lengthlength + length);
        List numbers = new ArrayList();
        while (!body.isEmpty()) {
            l = readNumber(body);
            int n = (int) l[0];
            int ll = (int) l[1];
            numbers.add(n);
            body = body.substring(ll);
        }
        int n0 = Integer.valueOf(numbers.remove(0).toString());
        int first = n0 / 40;
        int second = n0 - (40 * first);
        numbers.add(0, first);
        numbers.add(1, second);
        Object[] tuple = new Object[numbers.size()];
        return new Object[]{numbers.toArray(tuple), rest};
    }

    public static String[] removeBitString(String string) {
        if (string.charAt(0) != 0x03) {
            char n = string.charAt(0);
            throw new RuntimeException(String.format("wanted bitstring (0x03), got 0x%02x", (long) n));
        }
        long[] l = readLength(string.substring(1));
        int length = (int) l[0];
        int llen = (int) l[1];
        String body = string.substring(1 + llen, 1 + llen + length);
        String rest = string.substring(1 + llen + length);
        return new String[]{body, rest};
    }

    public static String[] removeOctetString(String string) {
        if (string.charAt(0) != 0x04) {
            char n = string.charAt(0);
            throw new RuntimeException(String.format("wanted octetstring (0x04), got 0x%02x", (long) n));
        }
        long[] l = readLength(string.substring(1));
        int length = (int) l[0];
        int llen = (int) l[1];
        String body = string.substring(1 + llen, 1 + llen + length);
        String rest = string.substring(1 + llen + length);
        return new String[]{body, rest};
    }

    public static Object[] removeConstructed(String string) {
        char s0 = string.charAt(0);
        if ((s0 & 0xe0) != 0xa0) {
            throw new RuntimeException(String.format("wanted constructed tag (0xa0-0xbf), got 0x%02x", (long) s0));
        }
        long tag = s0 & 0x1f;
        long[] l = readLength(string.substring(1));
        int length = (int) l[0];
        int llen = (int) l[1];
        String body = string.substring(1 + llen, 1 + llen + length);
        String rest = string.substring(1 + llen + length);
        return new Object[]{tag, body, rest};
    }

    public static String fromPem(String pem) {
        String[] pieces = pem.split("\n");
        StringBuilder d = new StringBuilder();
        for(String p : pieces) {
            if(!p.isEmpty() && !p.startsWith("-----")) {
                d.append(p.trim());
            }
        }
        try {
            return new String(Base64.decode(d.toString().getBytes()));
        } catch (IOException e) {
            throw new IllegalArgumentException("Corrupted pem string! Could not decode base64 from it");
        }
    }

    public static String toPem(String der, String name) {
        String b64 = Base64.encodeBytes(der.getBytes());
        StringBuilder lines = new StringBuilder();
        lines.append(String.format("-----BEGIN %s-----\n", name));
        for(int start=0; start< b64.length(); start+= 64) {
            lines.append(String.format("%s\n", b64.substring(start, start+64)));
        }
        lines.append(String.format("-----END %s-----\n", name));
        return lines.toString();
    }

}