package com.starkbank.ellipticcurve.utils;

public class Pem {
    
    static public String getPemContent(String pem, String template) {
        String[] piecesTemplate = template.split("\n%s");
        String[] piecesPem = pem.split("\n");
        StringBuilder content = new StringBuilder();
        boolean flag = false;
        for (String pemContent : piecesPem) {
            if (pemContent.equals(piecesTemplate[0])) {
                flag = true;
                continue;
            }
            if (pemContent.equals(piecesTemplate[1])) {
                flag = false;
                continue;
            }
            if (flag) content.append(pemContent);
        }
        return content.toString();
    }

    static public String createPem(String content, String template) {
        StringBuilder lines = new StringBuilder();
        for (int start = 0; start < content.length(); start += 64) {
            int end = Math.min(start + 64, content.length());
            lines.append(String.format("%s\n", content.substring(start, end)));
        }
        return String.format(template, lines.toString());
    }
}
