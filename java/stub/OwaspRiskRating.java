// A stub of the calculator's OwaspRiskRating, for one negative control of the Java check only: put first on the
// classpath, it shadows the JAR's class, so that Check4's sub-score check meets a calculator whose sub-scores are off
// the level sums, the one path of Check4 the JAR 1.0.1 never reaches. fromVector() accepts any 16-level vector; the
// Score it returns, the JAR's own class, carries the level sums for the likelihood and for the larger of the two
// impacts, and the smaller impact lowered by 0.25, so that the severity and the score, which read only those two,
// stay right.
// javac -cp <jar> -d <stub classes> OwaspRiskRating.java; java -cp <stub classes>:<jar>:<Check4 classes> Check4
package us.springett.owasp.riskrating;

public class OwaspRiskRating {
    private final int[] levels = new int[16];

    public static OwaspRiskRating fromVector(String vector) {
        OwaspRiskRating r = new OwaspRiskRating();
        String[] parts = vector.split("/");
        for (int i = 0; i < 16; i++) r.levels[i] = Integer.parseInt(parts[i].split(":")[1]);
        return r;
    }

    private double mean(int from, int to) {
        int s = 0;
        for (int i = from; i < to; i++) s += levels[i];
        return s / (double) (to - from);
    }

    public Score calculateScore() {
        double l = mean(0, 8), t = mean(8, 12), b = mean(12, 16);
        if (t >= b) {
            b -= 0.25;
        } else {
            t -= 0.25;
        }
        return new Score(l, t, b);
    }
}
