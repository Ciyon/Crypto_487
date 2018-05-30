import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.BitSet;

/**
 * Test driver for cSHAKE256 and KMACXOF256.
 *
 * @author Markku-Juhani Saarinen (original Keccak and SHAKE implementation in C)
 * @author Paulo S. L. M. Barreto (Java version, cSHAKE, KMACXOF)
 * @author Brandon Gaetaniello
 * @author Arwain Karlin
 */
public class Main {
    private static int test_hexdigit(char ch) {
        if (ch >= '0' && ch <= '9')
            return ch - '0';
        if (ch >= 'A' && ch <= 'F')
            return ch - 'A' + 10;
        if (ch >= 'a' && ch <= 'f')
            return ch - 'a' + 10;
        return -1;
    }

    private static int test_readhex(byte[] buf, String str, int maxbytes) {
        int i, h, l;

        for (i = 0; i < maxbytes; i++) {
            h = test_hexdigit(str.charAt(2 * i));
            if (h < 0) {
                return i;
            }
            l = test_hexdigit(str.charAt(2 * i + 1));
            if (l < 0) {
                return i;
            }
            buf[i] = (byte) ((h << 4) + l);
        }
        return i;
    }

    private static int memcmp(byte[] a, byte[] b, int len) {
        for (int i = 0; i < len; i++) {
            if (a[i] != b[i]) {
                return a[i] - b[i];
            }
        }
        return 0;
    }

    private static int test_shake() {
        // Test vectors have bytes 480..511 of XOF output for given inputs.
        // From http://csrc.nist.gov/groups/ST/toolkit/examples.html#aHashing

        String[] testhex = new String[]{
                // SHAKE256, message of length 0
                "AB0BAE316339894304E35877B0C28A9B1FD166C796B9CC258A064A8F57E27F2A",
                // SHAKE256, 1600-bit test pattern
                "6A1A9D7846436E4DCA5728B6F760EEF0CA92BF0BE5615E96959D767197A0BEEB"
        };

        SHAKE shake = new SHAKE();
        byte[] buf = new byte[32], ref = new byte[32];

        int fails = 0;

        for (int i = 0; i < testhex.length; i++) {

            shake.init256();

            if (i >= 1) {   // 1600-bit test pattern
                Arrays.fill(buf, 0, 20, (byte) 0xA3);
                for (int j = 0; j < 200; j += 20) {
                    shake.update(buf, 20);
                }
            }

            shake.xof();  // switch to extensible output

            for (int j = 0; j < 512; j += 32) { // output: discard bytes 0..479 (test only last 32 bytes)
                shake.out(buf, 32);
            }

            // compare to reference
            test_readhex(ref, testhex[i], ref.length);
            if (memcmp(buf, ref, 32) != 0) {
                System.out.println("[" + i + "] SHAKE256, len " + (i >= 1 ? 1600 : 0) + " test FAILED.");
                fails++;
            }
        }

        return fails;
    }

    /**
     * Convert an ASCII string to a byte array.
     *
     * @param s string to convert to a byte array
     * @return s converted to a byte array (all characters must be in range [0..255])
     */
    static byte[] asciiStringToByteArray(String s) {
        byte[] val = new byte[s.length()];
        for (int i = 0; i < val.length; i++) {
            char c = s.charAt(i);
            if (c >= 256) {
                throw new RuntimeException("Non-ASCII character found");
            }
            val[i] = (byte) c;
        }
        return val;
    }

    static String byteToHex(byte c) {
        String hex = "0123456789ABCDEF";
        String val = "";
        val += hex.charAt(((int) c >>> 4) & 0xF);
        val += hex.charAt((int) c & 0xF);
        return val;
    }

    private static void test_cshake256() {
        byte[] X_sample3 = new byte[]{(byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03};
        byte[] X_sample4 = new byte[200];
        for (int i = 0; i < X_sample4.length; i++) {
            X_sample4[i] = (byte) i;
        }
        byte[] out_sample3 = new byte[]{
                (byte) 0xD0, (byte) 0x08, (byte) 0x82, (byte) 0x8E, (byte) 0x2B, (byte) 0x80, (byte) 0xAC, (byte) 0x9D, (byte) 0x22, (byte) 0x18, (byte) 0xFF, (byte) 0xEE, (byte) 0x1D, (byte) 0x07, (byte) 0x0C, (byte) 0x48,
                (byte) 0xB8, (byte) 0xE4, (byte) 0xC8, (byte) 0x7B, (byte) 0xFF, (byte) 0x32, (byte) 0xC9, (byte) 0x69, (byte) 0x9D, (byte) 0x5B, (byte) 0x68, (byte) 0x96, (byte) 0xEE, (byte) 0xE0, (byte) 0xED, (byte) 0xD1,
                (byte) 0x64, (byte) 0x02, (byte) 0x0E, (byte) 0x2B, (byte) 0xE0, (byte) 0x56, (byte) 0x08, (byte) 0x58, (byte) 0xD9, (byte) 0xC0, (byte) 0x0C, (byte) 0x03, (byte) 0x7E, (byte) 0x34, (byte) 0xA9, (byte) 0x69,
                (byte) 0x37, (byte) 0xC5, (byte) 0x61, (byte) 0xA7, (byte) 0x4C, (byte) 0x41, (byte) 0x2B, (byte) 0xB4, (byte) 0xC7, (byte) 0x46, (byte) 0x46, (byte) 0x95, (byte) 0x27, (byte) 0x28, (byte) 0x1C, (byte) 0x8C
        };
        byte[] out_sample4 = new byte[]{
                (byte) 0x07, (byte) 0xDC, (byte) 0x27, (byte) 0xB1, (byte) 0x1E, (byte) 0x51, (byte) 0xFB, (byte) 0xAC, (byte) 0x75, (byte) 0xBC, (byte) 0x7B, (byte) 0x3C, (byte) 0x1D, (byte) 0x98, (byte) 0x3E, (byte) 0x8B,
                (byte) 0x4B, (byte) 0x85, (byte) 0xFB, (byte) 0x1D, (byte) 0xEF, (byte) 0xAF, (byte) 0x21, (byte) 0x89, (byte) 0x12, (byte) 0xAC, (byte) 0x86, (byte) 0x43, (byte) 0x02, (byte) 0x73, (byte) 0x09, (byte) 0x17,
                (byte) 0x27, (byte) 0xF4, (byte) 0x2B, (byte) 0x17, (byte) 0xED, (byte) 0x1D, (byte) 0xF6, (byte) 0x3E, (byte) 0x8E, (byte) 0xC1, (byte) 0x18, (byte) 0xF0, (byte) 0x4B, (byte) 0x23, (byte) 0x63, (byte) 0x3C,
                (byte) 0x1D, (byte) 0xFB, (byte) 0x15, (byte) 0x74, (byte) 0xC8, (byte) 0xFB, (byte) 0x55, (byte) 0xCB, (byte) 0x45, (byte) 0xDA, (byte) 0x8E, (byte) 0x25, (byte) 0xAF, (byte) 0xB0, (byte) 0x92, (byte) 0xBB
        };
        byte[] N = asciiStringToByteArray(""); // empty string
        /*
        System.out.println("encoding of N (length " + N.length + "):");
        for (int i = 0; i < N.length; i++) {
            System.out.print(byteToHex(N[i]));
        }
        System.out.println();
        //*/
        int L = 512;
        byte[] S = asciiStringToByteArray("Email Signature");
        /*
        System.out.println("string S: \"" + s + "\"");
        System.out.print("encoding of S (length " + S.length + "):");
        for (int i = 0; i < S.length; i++) {
            if ((i & 15) == 0) {
                System.out.print("\n    ");
            } else {
                System.out.print(" ");
            }
            System.out.print(byteToHex(S[i]));
        }
        System.out.println();
        //*/
        byte[] val_sample3 = SHAKE.cSHAKE256(X_sample3, L, N, S);
        byte[] val_sample4 = SHAKE.cSHAKE256(X_sample4, L, N, S);

        /*
        System.out.print("cSHAKE256 sample 3 [" + val_sample3.length + " bytes]:");
        for (int i = 0; i < val_sample3.length; i++) {
            if ((i & 15) == 0) {
                System.out.print("\n    ");
            } else {
                System.out.print(" ");
            }
            System.out.print(byteToHex(val_sample3[i]));
        }
        System.out.println();
        //*/
        if (!Arrays.equals(val_sample3, out_sample3)) {
            throw new RuntimeException("NIST sample 3 failure!");
        }
        /*
        System.out.print("cSHAKE256 sample 4 [" + val_sample4.length + " bytes]:");
        for (int i = 0; i < val_sample4.length; i++) {
            if ((i & 15) == 0) {
                System.out.print("\n    ");
            } else {
                System.out.print(" ");
            }
            System.out.print(byteToHex(val_sample4[i]));
        }
        System.out.println();
        //*/
        if (!Arrays.equals(val_sample4, out_sample4)) {
            throw new RuntimeException("NIST sample 4 failure!");
        }
        System.out.println("NIST SP 800-185/cSHAKE256 Sample Tests OK!");
    }

    private static void test_kmacxof256() {
        int L = 512;
        byte[] K = new byte[32];
        for (int i = 0; i < K.length; i++) {
            K[i] = (byte) (i + 0x40);
        }
        byte[] S = asciiStringToByteArray("My Tagged Application");

        byte[] X_sample4 = new byte[]{(byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03};
        byte[] X_sample5 = new byte[200];
        for (int i = 0; i < X_sample5.length; i++) {
            X_sample5[i] = (byte) i;
        }
        byte[] X_sample6 = X_sample5;

        byte[] out_sample4 = new byte[]{
                (byte) 0x17, (byte) 0x55, (byte) 0x13, (byte) 0x3F, (byte) 0x15, (byte) 0x34, (byte) 0x75, (byte) 0x2A, (byte) 0xAD, (byte) 0x07, (byte) 0x48, (byte) 0xF2, (byte) 0xC7, (byte) 0x06, (byte) 0xFB, (byte) 0x5C,
                (byte) 0x78, (byte) 0x45, (byte) 0x12, (byte) 0xCA, (byte) 0xB8, (byte) 0x35, (byte) 0xCD, (byte) 0x15, (byte) 0x67, (byte) 0x6B, (byte) 0x16, (byte) 0xC0, (byte) 0xC6, (byte) 0x64, (byte) 0x7F, (byte) 0xA9,
                (byte) 0x6F, (byte) 0xAA, (byte) 0x7A, (byte) 0xF6, (byte) 0x34, (byte) 0xA0, (byte) 0xBF, (byte) 0x8F, (byte) 0xF6, (byte) 0xDF, (byte) 0x39, (byte) 0x37, (byte) 0x4F, (byte) 0xA0, (byte) 0x0F, (byte) 0xAD,
                (byte) 0x9A, (byte) 0x39, (byte) 0xE3, (byte) 0x22, (byte) 0xA7, (byte) 0xC9, (byte) 0x20, (byte) 0x65, (byte) 0xA6, (byte) 0x4E, (byte) 0xB1, (byte) 0xFB, (byte) 0x08, (byte) 0x01, (byte) 0xEB, (byte) 0x2B
        };
        byte[] out_sample5 = new byte[]{
                (byte) 0xFF, (byte) 0x7B, (byte) 0x17, (byte) 0x1F, (byte) 0x1E, (byte) 0x8A, (byte) 0x2B, (byte) 0x24, (byte) 0x68, (byte) 0x3E, (byte) 0xED, (byte) 0x37, (byte) 0x83, (byte) 0x0E, (byte) 0xE7, (byte) 0x97,
                (byte) 0x53, (byte) 0x8B, (byte) 0xA8, (byte) 0xDC, (byte) 0x56, (byte) 0x3F, (byte) 0x6D, (byte) 0xA1, (byte) 0xE6, (byte) 0x67, (byte) 0x39, (byte) 0x1A, (byte) 0x75, (byte) 0xED, (byte) 0xC0, (byte) 0x2C,
                (byte) 0xA6, (byte) 0x33, (byte) 0x07, (byte) 0x9F, (byte) 0x81, (byte) 0xCE, (byte) 0x12, (byte) 0xA2, (byte) 0x5F, (byte) 0x45, (byte) 0x61, (byte) 0x5E, (byte) 0xC8, (byte) 0x99, (byte) 0x72, (byte) 0x03,
                (byte) 0x1D, (byte) 0x18, (byte) 0x33, (byte) 0x73, (byte) 0x31, (byte) 0xD2, (byte) 0x4C, (byte) 0xEB, (byte) 0x8F, (byte) 0x8C, (byte) 0xA8, (byte) 0xE6, (byte) 0xA1, (byte) 0x9F, (byte) 0xD9, (byte) 0x8B
        };
        byte[] out_sample6 = new byte[]{
                (byte) 0xD5, (byte) 0xBE, (byte) 0x73, (byte) 0x1C, (byte) 0x95, (byte) 0x4E, (byte) 0xD7, (byte) 0x73, (byte) 0x28, (byte) 0x46, (byte) 0xBB, (byte) 0x59, (byte) 0xDB, (byte) 0xE3, (byte) 0xA8, (byte) 0xE3,
                (byte) 0x0F, (byte) 0x83, (byte) 0xE7, (byte) 0x7A, (byte) 0x4B, (byte) 0xFF, (byte) 0x44, (byte) 0x59, (byte) 0xF2, (byte) 0xF1, (byte) 0xC2, (byte) 0xB4, (byte) 0xEC, (byte) 0xEB, (byte) 0xB8, (byte) 0xCE,
                (byte) 0x67, (byte) 0xBA, (byte) 0x01, (byte) 0xC6, (byte) 0x2E, (byte) 0x8A, (byte) 0xB8, (byte) 0x57, (byte) 0x8D, (byte) 0x2D, (byte) 0x49, (byte) 0x9B, (byte) 0xD1, (byte) 0xBB, (byte) 0x27, (byte) 0x67,
                (byte) 0x68, (byte) 0x78, (byte) 0x11, (byte) 0x90, (byte) 0x02, (byte) 0x0A, (byte) 0x30, (byte) 0x6A, (byte) 0x97, (byte) 0xDE, (byte) 0x28, (byte) 0x1D, (byte) 0xCC, (byte) 0x30, (byte) 0x30, (byte) 0x5D
        };
        byte[] val_sample4 = SHAKE.KMACXOF256(K, X_sample4, L, S);
        byte[] val_sample5 = SHAKE.KMACXOF256(K, X_sample5, L, null);
        byte[] val_sample6 = SHAKE.KMACXOF256(K, X_sample6, L, S);

        /*
        System.out.print("KMACXOF256 sample 4 [" + val_sample4.length + " bytes]:");
        for (int i = 0; i < val_sample4.length; i++) {
            if ((i & 15) == 0) {
                System.out.print("\n    ");
            } else {
                System.out.print(" ");
            }
            System.out.print(byteToHex(val_sample4[i]));
        }
        System.out.println();
        //*/
        if (!Arrays.equals(val_sample4, out_sample4)) {
            throw new RuntimeException("NIST sample 4 failure!");
        }
        /*
        System.out.print("KMACXOF256 sample 5 [" + val_sample5.length + " bytes]:");
        for (int i = 0; i < val_sample5.length; i++) {
            if ((i & 15) == 0) {
                System.out.print("\n    ");
            } else {
                System.out.print(" ");
            }
            System.out.print(byteToHex(val_sample5[i]));
        }
        System.out.println();
        //*/
        if (!Arrays.equals(val_sample5, out_sample5)) {
            throw new RuntimeException("NIST sample 5 failure!");
        }
        /*
        System.out.print("KMACXOF256 sample 6 [" + val_sample6.length + " bytes]:");
        for (int i = 0; i < val_sample6.length; i++) {
            if ((i & 15) == 0) {
                System.out.print("\n    ");
            } else {
                System.out.print(" ");
            }
            System.out.print(byteToHex(val_sample6[i]));
        }
        System.out.println();
        //*/
        if (!Arrays.equals(val_sample6, out_sample6)) {
            throw new RuntimeException("NIST sample 6 failure!");
        }
        System.out.println("NIST SP 800-185/KMACXOF256 Sample Tests OK!");
    }

    /**
     * Reference : https://stackoverflow.com/questions/5683206/how-to-create-an-array-of-20-random-bytes
     *
     * @return 8 random bytes
     */
    private static byte[] randomByte() {

        SecureRandom random = new SecureRandom();
        byte[] b = new byte[16];
        random.nextBytes(b);
        return b;

    }

    private static String hash(byte[] m) throws UnsupportedEncodingException {
        byte[] byteArr = SHAKE.KMACXOF256(asciiStringToByteArray(""), m, 512, asciiStringToByteArray("D"));
        StringBuilder hash = new StringBuilder();
        for (byte b : byteArr) {
            hash.append(byteToHex(b));
        }
        return hash.toString();
    }

    private static String decrypt(Cryptogram cryptogram, byte[] pw) throws UnsupportedEncodingException {
        Point z = cryptogram.getPoint();
        byte[] c = cryptogram.getCipherText();
        byte[] t = cryptogram.getMAC();
        BigInteger s = new BigInteger(SHAKE.KMACXOF256(pw, "".getBytes(),
                512, "K".getBytes())).multiply(BigInteger.valueOf(4));
        Point W = exponentiation(s, z);
        byte[] keka = SHAKE.KMACXOF256(W.getX().toByteArray(), "".getBytes(), 1024, asciiStringToByteArray("P"));
        byte[] ke = Arrays.copyOfRange(keka, 0, keka.length / 2);
        byte[] ka = Arrays.copyOfRange(keka, (keka.length / 2) + 1, keka.length - 1);
        byte[] m = SHAKE.KMACXOF256(ke, "".getBytes(), c.length * 8, asciiStringToByteArray("PKE"));
        for (int i = 0; i < m.length; i++) {
            m[i] ^= c[i];
        }
        byte[] tPrime = SHAKE.KMACXOF256(ka, m, 512, asciiStringToByteArray("PKA"));
        if (!Arrays.equals(t, tPrime)) {
            return new String(m, "UTF-8");
        }
        return "";
    }

    private static Cryptogram encrypt(byte[] m, Point V) {
        BigInteger k = new BigInteger(randomByte()).multiply(BigInteger.valueOf(4));
        Point G = new Point(BigInteger.valueOf(18), false);
        Point W = exponentiation(k, V);
        Point Z = exponentiation(k, G);
        byte[] keka = SHAKE.KMACXOF256(W.getX().toByteArray(), "".getBytes(), 1024, asciiStringToByteArray("P"));
        byte[] ke = Arrays.copyOfRange(keka, 0, keka.length / 2);
        byte[] ka = Arrays.copyOfRange(keka, (keka.length / 2) + 1, keka.length - 1);
        byte[] c = SHAKE.KMACXOF256(ke, "".getBytes(), m.length * 8, asciiStringToByteArray("PKE"));
        for (int i = 0; i < c.length; i++) {
            c[i] ^= m[i];
        }
        byte[] t = SHAKE.KMACXOF256(ka, m, 512, asciiStringToByteArray("PKA"));
        return new Cryptogram(Z, c, t);
    }

    private static Cryptogram encrypt(byte[] m, byte[] pw) {
        byte[] z = randomByte();
        byte[] keka = SHAKE.KMACXOF256(SHAKE.concat(z, pw), "".getBytes(), 1024, asciiStringToByteArray("S"));
        byte[] ke = Arrays.copyOfRange(keka, 0, keka.length / 2);
        byte[] ka = Arrays.copyOfRange(keka, (keka.length / 2) + 1, keka.length - 1);
        byte[] c = SHAKE.KMACXOF256(ke, "".getBytes(), m.length * 8, asciiStringToByteArray("SKE"));
        for (int i = 0; i < c.length; i++) {
            c[i] ^= m[i];
        }
        byte[] t = SHAKE.KMACXOF256(pw, m, 512, asciiStringToByteArray("T"));
        return new Cryptogram(z, c, t);
    }

    public static String decryptSymmetric(Cryptogram cryptogram, byte[] pw) throws UnsupportedEncodingException {
        byte[] z = cryptogram.getIV();
        byte[] c = cryptogram.getCipherText();
        byte[] t = cryptogram.getMAC();
        byte[] keka = SHAKE.KMACXOF256(SHAKE.concat(z, pw), "".getBytes(), 1024, asciiStringToByteArray("S"));
        byte[] ke = Arrays.copyOfRange(keka, 0, keka.length / 2);
        byte[] ka = Arrays.copyOfRange(keka, (keka.length / 2) + 1, keka.length - 1);
        byte[] m = SHAKE.KMACXOF256(ke, "".getBytes(), c.length * 8, asciiStringToByteArray("SKE"));
        for (int i = 0; i < m.length; i++) {
            m[i] ^= c[i];
        }
        byte[] tPrime = SHAKE.KMACXOF256(ka, m, 512, asciiStringToByteArray("SKA"));
        if (!Arrays.equals(t, tPrime)) {
            return new String(m, "UTF-8");
        }
        return "";

    }

    private static Point exponentiation(BigInteger x, Point G) {
        Point Y = G;
        for (int i = x.bitLength() - 1; i >= 0; i--) {
            Y.doubling();
            if (x.testBit(i)) {
                Y.sum(G);
            }
        }

        return Y;
    }

    private static void generateKeyPair(byte[] pw) throws IOException {
        Point G = new Point(BigInteger.valueOf(18), false);
        BigInteger s = new BigInteger(SHAKE.KMACXOF256(pw, "".getBytes(),
                512, "K".getBytes())).multiply(BigInteger.valueOf(4)).abs();

        Point V = exponentiation(s, G);
        Files.write(Paths.get("PublicX.txt"), V.getX().toByteArray());
        Files.write(Paths.get("PublicY.txt"), V.getY().toByteArray());

        Cryptogram crypt = encrypt(s.toByteArray(), pw);

        Files.write(Paths.get("IV.txt"), crypt.getIV());
        Files.write(Paths.get("ciphertext.txt"), crypt.getCipherText());
        Files.write(Paths.get("MAC.txt"), crypt.getMAC());

    }

    private static void generateSignature(byte[] m, byte[] pw) throws IOException {
        BigInteger s = new BigInteger(SHAKE.KMACXOF256(pw, "".getBytes(), 512, "K".getBytes())).multiply(BigInteger.valueOf(4));
        BigInteger k = new BigInteger(SHAKE.KMACXOF256(s.toByteArray(), m, 512, "N".getBytes()));
        Point G = new Point(BigInteger.valueOf(18), false);
        Point U = exponentiation(k, G);
        BigInteger h = new BigInteger(SHAKE.KMACXOF256(U.getX().toByteArray(), m, 512, "T".getBytes()));
        BigInteger r = BigInteger.valueOf(2).pow(519).subtract(new BigInteger("337554763258501705789107630418782636071904961214051226618635150085779108655765"));
        BigInteger z = k.subtract(h.multiply(s)).mod(r);
        Files.write(Paths.get("signature.txt"), h.toByteArray());
        Files.write(Paths.get("signature.txt"), z.toByteArray(), StandardOpenOption.APPEND);
        System.out.println("Signature written to signature.txt.");
    }

    private static byte[] readFile(File theFile) throws IOException {
        byte[] byteArr;
        if (theFile.exists() && theFile.isFile()) {
            byteArr = Files.readAllBytes(theFile.toPath());
        } else {
            if (!theFile.isFile()) {
                throw new IllegalArgumentException("File input must be a file.");
            } else {
                throw new IllegalArgumentException("File name not found.");
            }
        }

        return byteArr;
    }

    public static void main(String[] args) throws IOException {
        switch (args[0]) {
            case "-hash":
                if (args[1].equals("-f") && args[2] != null) {
                    String h = hash(readFile(new File(args[2])));
                    System.out.println(h);
                    break;

                } else if (args[1].equals("-m") && args[2] != null) {
                    System.out.println(hash(asciiStringToByteArray(args[2])));
                    break;
                } else {
                    throw new IllegalArgumentException("Please provide appropriate input");
                }
            case "-gen":
                if (args[1].equals("-pw") && args[2] != null) {
                    generateKeyPair(asciiStringToByteArray(args[2]));
                    System.out.println("Outputted public key to PublicX and PublicY.txt");
                    System.out.println("Outputted private key to IV.txt, MAC.txt, ciphertext.txt");
                    break;
                } else {
                    throw new IllegalArgumentException("Please provide appropriate input");
                }
            case "-gensig":
                if (args[1].equals("-m") && args[2] != null) {
                    if (args[3].equals("-pw") && args[4] != null)
                    {
                        generateSignature(args[2].getBytes(), args[4].getBytes());
                    }
                    break;
                } else {
                    throw new IllegalArgumentException("Please provide appropriate input");
                }


            case "-enc":
                if (args[1].equals("-f") && args[2] != null) {
                    if (args[3].equals("-pw") && args[4] != null) {
                        Cryptogram gram = encrypt(readFile((new File(args[2]))), asciiStringToByteArray(args[4]));

                        Files.write(Paths.get("IV.txt"), gram.getIV());
                        Files.write(Paths.get("ciphertext.txt"), gram.getCipherText());
                        Files.write(Paths.get("MAC.txt"), gram.getMAC());
                        break;

                    }
                } else if (args[1].equals("-m") && args[2] != null) {
                    if (args[3].equals("-k")) {
                        BigInteger x = new BigInteger(Files.readAllBytes(Paths.get("PublicX.txt")));
                        BigInteger y = new BigInteger(Files.readAllBytes(Paths.get("PublicY.txt")));
                        Point publicKey = new Point(x, y);
                        Cryptogram gram = encrypt(args[2].getBytes(), publicKey);

                        Files.write(Paths.get("PublicY.txt"), gram.getPoint().getY().toByteArray());
                        Files.write(Paths.get("PublicX.txt"), gram.getPoint().getX().toByteArray());
                        Files.write(Paths.get("ciphertext.txt"), gram.getCipherText());
                        Files.write(Paths.get("MAC.txt"), gram.getMAC());
                        break;
                    }
                    if (args[3].equals("-pw") && args[4] != null) {
                        Cryptogram gram = encrypt(asciiStringToByteArray(args[2]), asciiStringToByteArray(args[4]));

                        Files.write(Paths.get("IV.txt"), gram.getIV());
                        Files.write(Paths.get("ciphertext.txt"), gram.getCipherText());
                        Files.write(Paths.get("MAC.txt"), gram.getMAC());
                        break;
                    }
                }
                else {
                    throw new IllegalArgumentException("Please provide appropriate input");
                }
            case "-dec":
                if (args[1].equals("-pw")) {

                    byte[] IV;
                    byte[] cText;
                    byte[] MAC;

                    IV = Files.readAllBytes(Paths.get("IV.txt"));
                    cText = Files.readAllBytes(Paths.get("ciphertext.txt"));
                    MAC = Files.readAllBytes(Paths.get("MAC.txt"));
                    Cryptogram gram = new Cryptogram(IV, cText, MAC);
                    System.out.println("Decrypted Message is: " + decryptSymmetric(gram, asciiStringToByteArray(args[2])));
                    break;
                } else {
                    throw new IllegalArgumentException("Please provide appropriate input");
                }
            case "-kdec":
                if (args[1].equals("-pw")) {

                    byte[] cText;
                    byte[] MAC;

                    BigInteger x = new BigInteger(Files.readAllBytes(Paths.get("PublicX.txt")));
                    BigInteger y = new BigInteger(Files.readAllBytes(Paths.get("PublicY.txt")));
                    Point Z = new Point (x, y);
                    cText = Files.readAllBytes(Paths.get("ciphertext.txt"));
                    MAC = Files.readAllBytes(Paths.get("MAC.txt"));
                    Cryptogram gram = new Cryptogram(Z, cText, MAC);
                    System.out.println("Decrypted Message is: " + decrypt(gram, asciiStringToByteArray(args[2])));
                    break;
                } else {
                    throw new IllegalArgumentException("Please provide appropriate input");
                }
            default:
                throw new IllegalArgumentException("Please provide appropriate input");
        }
//
//        if (test_shake() == 0) {
//            System.out.println("FIPS 202/SHAKE256 Self-Tests OK!");
//        }
//
//        test_cshake256();
//        test_kmacxof256();
//
    }

}
