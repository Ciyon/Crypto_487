
/**
 * @author Brandon Gaetaniello
 * @author Arwain Karlin
 */
public class Cryptogram {

    public byte[] getIV() {
        return IV;
    }

    public Point getPoint() {
        return point;
    }

    public byte[] getCipherText() {
        return cipherText;
    }

    public byte[] getMAC() {
        return MAC;
    }

    private byte[] IV;
    private byte[] cipherText;
    private byte[] MAC;
    private Point point;

    public Cryptogram(byte[] z, byte[] c, byte[] t) {
        IV = z;
        cipherText = c;
        MAC = t;
    }

    public Cryptogram(Point z, byte[] c, byte[] t) {
        point = z;
        cipherText = c;
        MAC = t;
    }

}
