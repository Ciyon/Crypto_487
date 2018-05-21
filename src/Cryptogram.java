
/**
 * @author Brandon Gaetaniello
 * @author Arwain Karlin
 */
public class Cryptogram {

    public byte[] getIV() {
        return IV;
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

    public Cryptogram(byte[] z, byte[] c, byte[] t) {
        IV = z;
        cipherText = c;
        MAC = t;
    }

}
