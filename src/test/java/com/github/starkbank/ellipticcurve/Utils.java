package com.github.starkbank.ellipticcurve;

import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Objects;

/**
 * Created on 17-Jan-19
 *
 * @author Taron Petrosyan
 */
class Utils {

    static String readFileAsString(String path) throws URISyntaxException, IOException {
        return new String(Files.readAllBytes(Paths.get(Objects.requireNonNull(ClassLoader.getSystemClassLoader().getResource(path)).toURI())));

    }

    static byte[] readFileAsBytes(String path) throws URISyntaxException, IOException {
        return Files.readAllBytes(Paths.get(Objects.requireNonNull(ClassLoader.getSystemClassLoader().getResource(path)).toURI()));

    }
}
