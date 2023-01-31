package com.starkbank.ellipticcurve.utils;
import java.util.ArrayList;
import java.util.List;

import static java.lang.Math.floorDiv;

public class Oid {
    
    static public List<Integer> oidFromHex(String hexadecimal) {
        String firstByte = hexadecimal.substring(0, 2);
        String remainingBytes = hexadecimal.substring(2);
        int firstByteInt = Binary.intFromHex(firstByte).intValue();
        List<Integer> oid = new ArrayList<Integer>();
        oid.add(floorDiv(firstByteInt, 40));
        oid.add(firstByteInt % 40);
        int oidInt = 0;
        while( remainingBytes.length() > 0 ) {
            String byteString = remainingBytes.substring(0, 2);
            remainingBytes = remainingBytes.substring(2);
            int byteInt = Binary.intFromHex(byteString).intValue();
            if (byteInt >= 128){
                oidInt = (128 * oidInt) + (byteInt - 128);
                continue;
            }
            oidInt = (128 * oidInt) + byteInt;
            oid.add(oidInt);
            oidInt = 0;
        }
        return oid;
    }

    static public String oidToHex(long[] oid) {
        List<Long> oidList = new ArrayList<Long>();
        for(long e : oid){ oidList.add(e); }
        StringBuilder hexadecimal = new StringBuilder(Binary.hexFromInt(40 * oidList.get(0) + oidList.get(1)));
        for (Long number : oidList.subList(2, oidList.size())) {
            hexadecimal.append(oidNumberToHex(number));
        }
        return hexadecimal.toString();
    }

    static private String oidNumberToHex(long number) {
        String hexadecimal = "";
        int endDelta = 0;
        while (number > 0) {
            hexadecimal = Binary.hexFromInt((number % 128) + endDelta) + hexadecimal;
            number = floorDiv(number, 128);
            endDelta = 128;
        }
        return !hexadecimal.equals("") ? hexadecimal : "00";
    }

}
