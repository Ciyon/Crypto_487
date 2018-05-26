import java.math.BigInteger;

public class Point {

    public static BigInteger myP = BigInteger.valueOf(2).pow(521).subtract(BigInteger.ONE);
    public static BigInteger E_521;
    public static BigInteger d = BigInteger.valueOf(-376014);
    public BigInteger myX;
    public BigInteger myY;

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
        myX = x;
    }

    public BigInteger getX() {
        return myX;
    }

    public BigInteger getY() {
        return myY;
    }


    public Point sum(Point a) {
        BigInteger xNum = this.myX.multiply(a.myY).add(this.myY.multiply(a.myX)).mod(myP);
        BigInteger xDen = BigInteger.ONE.add(d.multiply(this.myX).multiply(a.myX).multiply(this.myY).multiply(this.myX)).modInverse(myP);
        BigInteger yNum = this.myY.multiply(a.myY).subtract(this.myX.multiply(a.myX)).mod(myP);
        BigInteger yDen = BigInteger.ONE.subtract(d.multiply(this.myX).multiply(a.myX).multiply(this.myY).multiply(a.myY)).modInverse(myP);
        return new Point(xNum.divide(xDen), yNum.divide(yDen));
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

}
