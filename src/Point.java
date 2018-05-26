import java.math.BigInteger;

public class Point {

    private static BigInteger myP  = BigInteger.valueOf(2).pow(521).subtract(BigInteger.ONE);
    public static BigInteger myX;
    public static BigInteger myY;
    private static BigInteger E_521;
    private static BigInteger d = BigInteger.valueOf(-376014);

    public Point(){
        myX = BigInteger.ZERO;
        myY = BigInteger.ONE;
    }

    public Point(BigInteger x, BigInteger y){
        myX = x;
        myY = y;
        E_521 = BigInteger.ONE.add(d.multiply(myX.pow(2)).multiply(myY.pow(2)));
        System.out.println(E_521);
    }

    public Point(BigInteger x, boolean sigBit){
        myX = x;
    }

    public static Point sum(Point a, Point b){
        BigInteger xNum = a.myX.multiply(b.myY).add(a.myY.multiply(b.myX)).mod(myP);
        BigInteger xDen = BigInteger.ONE.add(d.multiply(a.myX).multiply(b.myX).multiply(a.myY).multiply(a.myX)).modInverse(myP);
        BigInteger yNum = a.myY.multiply(b.myY).subtract(a.myX.multiply(b.myX)).mod(myP);
        BigInteger yDen = BigInteger.ONE.subtract(d.multiply(a.myX).multiply(b.myX).multiply(a.myY).multiply(b.myY)).modInverse(myP);
        return new Point(xNum.divide(xDen), yNum.divide(yDen));
    }


//    public boolean equals(Point a, Point b){
//        // TODO
//    }



}
