package com.starkbank.ellipticcurve.utils;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.time.ZoneId;
import java.util.*;


public class Der {

    private Der() {
        throw new UnsupportedOperationException("Der is a utility class and cannot be instantiated");
    }

    static public final class DerFieldType {
        static final public String Integer = "integer";
        static final public String BitString = "bitString";
        static final public String OctetString = "octetString";
        static final public String Null = "null";
        static final public String Object = "object";
        static final public String PrintableString = "printableString";
        static final public String UtcTime = "utcTime";
        static final public String Sequence = "sequence";
        static final public String Set = "set";
        static final public String OidContainer = "oidContainer";
        static final public String PublicKeyPointContainer = "publicKeyPointContainer";
    }

    static private final HashMap<String, String> hexTagToType = new HashMap<String, String>() {
        {
            put("02", DerFieldType.Integer);
            put("03", DerFieldType.BitString);
            put("04", DerFieldType.OctetString);
            put("05", DerFieldType.Null);
            put("06", DerFieldType.Object);
            put("13", DerFieldType.PrintableString);
            put("17", DerFieldType.UtcTime);
            put("30", DerFieldType.Sequence);
            put("31", DerFieldType.Set);
            put("a0", DerFieldType.OidContainer);
            put("a1", DerFieldType.PublicKeyPointContainer);
        }
    };

    static private final HashMap<String, String> typeToHexTag = new HashMap<String, String>() {
        {
            for (String key : hexTagToType.keySet()) {
                put(hexTagToType.get(key), key);
            }
        }
    };

    static public String encodeConstructed(String... encodedValues) {
        StringBuilder stringPieces = new StringBuilder("");
        for (String p : encodedValues) {
            stringPieces.append(p);
        }
        return encodePrimitive(DerFieldType.Sequence, stringPieces.toString());
    }

    static public String encodePrimitive(String tagType, Object value) {
        if(Objects.equals(tagType, DerFieldType.Integer)) value = encodeInteger(new BigInteger((String) value));
        if(Objects.equals(tagType, DerFieldType.Object)) value = Oid.oidToHex((long []) value);
        
        return "" + typeToHexTag.get(tagType) + generateLengthBytes((String) value) + value;
    }

    static private String encodeInteger(BigInteger number) {
        String hexadecimal = Binary.hexFromInt(number.abs());
        if(number.signum() == -1) {
            int bitCount = 4 * hexadecimal.length();
            BigInteger twosComplement = number.add(BigInteger.valueOf((long) Math.pow(2, bitCount)));
            return Binary.hexFromInt(twosComplement);
        }
        char firstChar = hexadecimal.charAt(0);
        String bits = Binary.bitsFromHex(String.valueOf(firstChar));
        if(bits.charAt(0) == '1') hexadecimal = "00" + hexadecimal;
        return hexadecimal;
    }

    static public Object[] parse(String hexadecimal) throws Exception {
        if(Objects.equals(hexadecimal, "")) return new Object[]{};
        String typeByte = hexadecimal.substring(0, 2);
        hexadecimal = hexadecimal.substring(2);

        int[] lengthArray = readLengthBytes(hexadecimal);
        int length = lengthArray[0];
        int lengthBytes = lengthArray[1];

        String content = hexadecimal.substring(lengthBytes, lengthBytes + length);
        hexadecimal = hexadecimal.substring(lengthBytes + length);
        if(content.length() < length) throw new Exception("missing bytes in DER parse");

        HashMap<String, Object> tagData = getTagData(typeByte);
        
        if(tagData.get("isConstructed").equals(true)) {
            
            Object[] nextContent = parse(hexadecimal);
            if(nextContent.length == 0) {
                return new Object[]{ parse(content) };
            }
            return new Object[]{ parse(content), nextContent[0] };
        }
        
        List<Object> contentArray = new ArrayList<Object>();
        switch((String) tagData.get("type")) {
            case DerFieldType.Null:
                contentArray.add(parseNull(content));
                break;
            case DerFieldType.Object:
                contentArray.add(parseOid(content));
                break;
            case DerFieldType.UtcTime:
                contentArray.add(parseTime(content));
                break;
            case DerFieldType.Integer:
                contentArray.add(parseInteger(content));
                break;
            case DerFieldType.PrintableString:
                contentArray.add(parseString(content));
                break;
            default:
                contentArray.add(parseAny(content));
                break;
        }

        if(hexadecimal.length() != 0) contentArray.add(parse(hexadecimal));

        return contentArray.toArray();
    }

    static private String parseAny(String hexadecimal) {
        return hexadecimal;
    }

    static private List<Integer> parseOid(String hexadecimal) {
        return Oid.oidFromHex(hexadecimal);
    }
    
    static public String parseTime(String hexadecimal) throws ParseException {
        String string = parseString(hexadecimal);
        DateFormat format = new SimpleDateFormat("yyMMddHHmmss");
        TimeZone tz = TimeZone.getTimeZone(ZoneId.of(string.substring(string.length() - 1)));
        format.setTimeZone(tz);
        Date parsed = format.parse(string);
        return parsed.toInstant().toString();
    }
    
    static private String parseString(String hexadecimal) {
        byte[] bytes = Binary.byteFromHex(hexadecimal);
        return new String(bytes, StandardCharsets.UTF_8);
    }

    static private String parseNull(String hexadecimal) {
        return null;
    }

    static private BigInteger parseInteger(String hexadecimal) {
        BigInteger integer = Binary.intFromHex(hexadecimal);
        String bits = Binary.bitsFromHex(hexadecimal.charAt(0));
        if(bits.charAt(0) == '0') return integer;
        int bitCount = 4 * hexadecimal.length();
        return integer.subtract(BigInteger.valueOf((long) Math.pow(2, bitCount)));
    }
    
    static private int[] readLengthBytes(String hexadecimal) throws Exception {
        int lengthBytes = 2;
        int lengthIndicator = Binary.intFromHex(hexadecimal.substring(0, lengthBytes)).intValue();
        boolean isShortForm = lengthIndicator < 128;
        if(isShortForm) {
            int length = 2 * lengthIndicator;
            return new int[] {length, lengthBytes};
        }
        int lengthLength = lengthIndicator - 128;
        if(lengthLength == 0) throw new Exception("indefinite length encoding located in DER");
        lengthBytes += 2 * lengthLength;
        int length = Binary.intFromHex(hexadecimal.substring(2, lengthBytes)).intValue() * 2;
        return new int[] {length, lengthBytes};
    }
    
    static private String generateLengthBytes(String hexadecimal) {
        BigInteger size = BigInteger.valueOf(hexadecimal.length()).divide(BigInteger.valueOf(2));
        String length = Binary.hexFromInt(size);
        if(size.compareTo(BigInteger.valueOf(128)) < 0) return Binary.padLeftZeros(length, 2);
        BigInteger lengthLength = BigInteger.valueOf(length.length()).divide(BigInteger.valueOf(2)).add(BigInteger.valueOf(128));
        return Binary.hexFromInt(lengthLength) + length;
    }

    static private HashMap<String, Object> getTagData(String tag) {
        char[] bits = Binary.bitsFromHex(tag).toCharArray();
        char bits8 = bits[0];
        char bits7 = bits[1];
        char bits6 = bits[2];

        HashMap<String, HashMap<String, String>> tagHashMap = new HashMap<String, HashMap<String, String>>();
        HashMap<String, String> param0 = new HashMap<String, String>();
        param0.put("0", "universal");
        param0.put("1", "application");
        HashMap<String, String> param1 = new HashMap<String, String>();
        param1.put("0", "context-specific");
        param1.put("1", "private");
        tagHashMap.put("0", param0);
        tagHashMap.put("1", param1);
        
        String tagClass = tagHashMap.get(String.valueOf(bits8)).get(String.valueOf(bits7));
        Boolean isConstructed = bits6 == '1';

        HashMap<String, Object> data = new HashMap<String, Object>();
        data.put("class", tagClass);
        data.put("isConstructed", isConstructed);
        data.put("type", hexTagToType.get(tag));
        return data;
    }
}