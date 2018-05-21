
import java.security.SecureRandom;
import java.util.Arrays;

public class Cryptogram {

    public byte[] getZ() {
        return myZ;
    }

    public byte[] getC() {
        return myC;
    }

    public byte[] getT() {
        return myT;
    }

    private byte[] myZ;
    private byte[] myC;
    private byte[] myT;

    public Cryptogram(byte[] z, byte[] c, byte[] t) {
        myZ = z;
        myC = c;
        myT = t;
    }






//    public static void main(String[] happy) {
//
//        Cryptogram c = new Cryptogram();
//        byte[] a = new byte[8];
//        a = c.randomByte();
//        System.out.println(Arrays.toString(a));
//    }

}
