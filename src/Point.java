import java.math.BigInteger;

public class Point {

    public static BigInteger myP = BigInteger.valueOf(2).pow(521).subtract(BigInteger.ONE);
    public static BigInteger E_521;
    public static BigInteger d = BigInteger.valueOf(-376014);
    private BigInteger myX;
    private BigInteger myY;

    public Point() {
        myX = BigInteger.ZERO;
        myY = BigInteger.ONE;
    }

    public Point(BigInteger x, BigInteger y) {
        myX = x;
        myY = y;
        E_521 = BigInteger.ONE.add(d.multiply(myX.pow(2)).multiply(myY.pow(2)));
        //System.out.println(E_521);
    }

    public Point(BigInteger x, boolean sigBit) {
        BigInteger xpow2 = BigInteger.valueOf(18).pow(2);
        BigInteger radicand = BigInteger.ONE.subtract(xpow2).multiply((BigInteger.ONE.add(BigInteger.valueOf(376014).multiply(xpow2)).mod(myP)).modInverse(myP));
        BigInteger y = Point.sqrt(radicand, myP, sigBit);
        myX = x;
        myY = y;
    }

    BigInteger getX() {
        return myX;
    }

    BigInteger getY() {
        return myY;
    }


    void sum(Point a) {
        BigInteger xNum = this.getX().multiply(a.getY()).add(this.getY().multiply(a.getX())).mod(myP);
        BigInteger xDen = BigInteger.ONE.add(d.multiply(this.getX()).multiply(a.getX()).multiply(this.getY()).multiply(a.getY())).modInverse(myP);
        BigInteger yNum = this.getY().multiply(a.getY()).subtract(this.getX().multiply(a.getX())).mod(myP);
        BigInteger yDen = BigInteger.ONE.subtract(d.multiply(this.getX()).multiply(a.getX()).multiply(this.getY()).multiply(a.getY())).modInverse(myP);
        myX = xDen.multiply(xNum).mod(myP);
        myY = yDen.multiply(yNum).mod(myP);
    }

    void doubling()
    {
        BigInteger xNum = BigInteger.TWO.multiply(this.getX()).multiply(this.getY()).mod(myP);
        BigInteger xDen = this.getX().pow(2).add(this.getY().pow(2)).modInverse(myP);
        BigInteger yNum = this.getY().pow(2).subtract(this.getX().pow(2)).mod(myP);
        BigInteger yDen = BigInteger.TWO.subtract(this.getX().pow(2)).subtract(this.getY().pow(2)).modInverse(myP);
        myX = xDen.multiply(xNum).mod(myP);
        myY = yDen.multiply(yNum).mod(myP);
    }


    public boolean equals(Point a) {
        if ((this.myX.compareTo(a.myX) == 0) && (this.myY.compareTo(a.myY) == 0)) {
            return true;
        }
        return false;
    }

    public Point opposite(){
        return new Point(this.myX.negate(), this.myY);
    }

    /**
     * Compute a square root of v mod p with a specified
     * least significant bit, if such a root exists.
     *
     * @param v the radicand.
     * @param p the modulus (must satisfy p mod 4 = 3).
     * @param lsb desired least significant bit (true: 1, false: 0).
     * @return a square root r of v mod p with r mod 2 = 1 iff lsb = true
     * if such a root exists, otherwise null.
     */
    public static BigInteger sqrt(BigInteger v, BigInteger p, boolean lsb) {
        assert (p.testBit(0) && p.testBit(1)); // p = 3 (mod 4)
        if (v.signum() == 0) {
            return BigInteger.ZERO;
        }
        BigInteger r = v.modPow(p.shiftRight(2).add(BigInteger.ONE), p);
        if (r.testBit(0) != lsb) {
            r = p.subtract(r); // correct the lsb
        }
        return (r.multiply(r).subtract(v).mod(p).signum() == 0) ? r : null;
    }

}
