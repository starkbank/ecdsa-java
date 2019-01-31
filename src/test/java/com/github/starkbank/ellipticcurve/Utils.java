package com.github.starkbank.ellipticcurve;

import java.io.IOException;
import java.io.RandomAccessFile;
import java.net.URISyntaxException;

/**
 * Created on 17-Jan-19
 *
 * @author Taron Petrosyan
 */
class Utils {

    static String readFileAsString(String path) throws URISyntaxException, IOException {
        return new String(readFileAsBytes(path), "ASCII");
    }

    static byte[] readFileAsBytes(String path) throws URISyntaxException {
        return read(ClassLoader.getSystemClassLoader().getResource(path).toURI().getPath());
    }

    private static byte[] read(String path) {
        try {
            RandomAccessFile f = new RandomAccessFile(path, "r");
            if (f.length() > Integer.MAX_VALUE)
                throw new RuntimeException("File is too large");
            byte[] b = new byte[(int) f.length()];
            f.readFully(b);
            if (f.getFilePointer() != f.length())
                throw new RuntimeException("File length changed while reading");
            return b;
        } catch (IOException e) {
            throw new RuntimeException("Could not read file");
        }
    }
}
