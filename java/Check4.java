// Check4: the OWASP reference calculator, us.springett:owasp-risk-rating-calculator 1.0.1, over every OWASP rating
// of the VEX files the chain collects. Each vector is parsed and scored by the calculator, and the published severity
// and score are compared with what its levels give. No network.
// Input on stdin, UTF-8, tab-separated, each VEX declared before its ratings:
//   #vex TAB label TAB vex TAB kind TAB expected CVE ids, comma-separated     kind: after, before or refused
//   label TAB vex TAB vulnId TAB vector TAB severity TAB score
// one line per OWASP rating, and one with an empty vector for a CVE the VEX lists without one.
// after: every vector parses and scores, its sub-scores are the level sums /8, /4, /4, its severity OWASP's matrix on
// the calculator's bands with max(T, B), its score L x max(T, B). before: vens main's vectors; a refused one's other
// checks are not applicable, and an accepted one's severity and score follow main's own rule, checked apart.
// refused: a control the calculator must refuse. Every VEX: its CVE ids exactly the ids declared, each rated once.
// Prints one line per label, then a last line; exits 1 if any label fails.
// javac -cp <jar> -d <classes> Check4.java; java -cp <jar>:<classes> Check4 < ratings.tsv
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import us.springett.owasp.riskrating.Level;
import us.springett.owasp.riskrating.OwaspRiskRating;
import us.springett.owasp.riskrating.Score;

public class Check4 {
    // OWASP's Step 4: rows the likelihood band LOW, MEDIUM, HIGH; columns the impact band; Note written info
    static final String[][] MATRIX = {{"info", "low", "medium"}, {"low", "medium", "high"}, {"medium", "high", "critical"}};

    static int band(Level l) {
        return l == Level.LOW ? 0 : (l == Level.MEDIUM ? 1 : 2);
    }

    static int sum(String vector, int from, int to) {
        String[] parts = vector.split("/");
        int s = 0;
        for (int i = from; i < to; i++) s += Integer.parseInt(parts[i].split(":")[1]);
        return s;
    }

    static final class Vex {
        final String label;
        final Set<String> expected;
        final Map<String, Integer> lines = new HashMap<>();

        Vex(String label, Set<String> expected) {
            this.label = label;
            this.expected = expected;
        }
    }

    static final class Tally {
        final String kind;
        long vexes, cves, absent, extra, missing, twice, vectors, refused, subOff, subNa, sevOff, sevNa, scoreOff, scoreNa;

        Tally(String kind) {
            this.kind = kind;
        }

        List<String> failures() {
            List<String> f = new ArrayList<>();
            if (absent > 0) f.add("a CVE of the report missing from the VEX");
            if (extra > 0) f.add("a CVE the report does not hold");
            if (missing > 0) f.add("a CVE without an OWASP rating");
            if (twice > 0) f.add("a CVE rated twice");
            if (kind.equals("after") && refused > 0) f.add("an after vector refused");
            if (kind.equals("refused") && refused < vectors) f.add("a control vector accepted");
            if (subOff > 0) f.add("sub-scores off the level sums");
            if (sevOff > 0) f.add("a severity off the matrix");
            if (scoreOff > 0) f.add("a score off L x max(T, B)");
            return f;
        }
    }

    public static void main(String[] args) throws Exception {
        Map<String, Vex> vexes = new LinkedHashMap<>();
        Map<String, Tally> labels = new TreeMap<>();
        BufferedReader in = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
        for (String line; (line = in.readLine()) != null; ) {
            if (line.isEmpty()) continue;
            String[] f = line.split("\t", -1);
            if (f[0].equals("#vex")) {
                String kind = f[3];
                if (!kind.equals("after") && !kind.equals("before") && !kind.equals("refused"))
                    throw new IllegalArgumentException("unknown kind " + kind);
                if (vexes.containsKey(f[2])) throw new IllegalArgumentException("a VEX declared twice: " + f[2]);
                Set<String> ids = new HashSet<>(Arrays.asList(f[4].split(",")));
                ids.remove("");
                vexes.put(f[2], new Vex(f[1], ids));
                Tally t = labels.computeIfAbsent(f[1], k -> new Tally(kind));
                if (!t.kind.equals(kind)) throw new IllegalArgumentException("a label of two kinds: " + f[1]);
                t.vexes++;
                continue;
            }
            Vex v = vexes.get(f[1]);
            if (v == null || !v.label.equals(f[0]))
                throw new IllegalArgumentException("a rating before its VEX's declaration: " + f[1]);
            Tally t = labels.get(f[0]);
            v.lines.merge(f[2], 1, Integer::sum);
            String vector = f[3], severity = f[4];
            if (vector.isEmpty()) {
                t.missing++;
                continue;
            }
            t.vectors++;
            Score s;
            try {
                s = OwaspRiskRating.fromVector(vector).calculateScore();
            } catch (Exception e) {
                t.refused++;
                t.subNa++;
                t.sevNa++;
                t.scoreNa++;
                continue;
            }
            if (t.kind.equals("refused")) {
                t.subNa++;
                t.sevNa++;
                t.scoreNa++;
                continue;
            }
            double l = s.getLikelihoodScore(), tech = s.getTechnicalImpactScore(), bus = s.getBusinessImpactScore();
            if (l != sum(vector, 0, 8) / 8.0 || tech != sum(vector, 8, 12) / 4.0 || bus != sum(vector, 12, 16) / 4.0)
                t.subOff++;
            if (t.kind.equals("before")) {
                t.sevNa++;
                t.scoreNa++;
                continue;
            }
            Level impact = tech >= bus ? s.getTechnicalImpact() : s.getBusinessImpact();
            if (!MATRIX[band(s.getLikelihood())][band(impact)].equals(severity)) t.sevOff++;
            if (l * Math.max(tech, bus) != Double.parseDouble(f[5])) t.scoreOff++;
        }
        for (Vex v : vexes.values()) {
            Tally t = labels.get(v.label);
            t.cves += v.lines.size();
            for (String id : v.expected) if (!v.lines.containsKey(id)) t.absent++;
            for (String id : v.lines.keySet()) if (!v.expected.contains(id)) t.extra++;
            for (int n : v.lines.values()) if (n > 1) t.twice++;
        }
        int failed = 0;
        for (Map.Entry<String, Tally> e : labels.entrySet()) {
            Tally t = e.getValue();
            List<String> f = t.failures();
            if (!f.isEmpty()) failed++;
            System.out.println(e.getKey() + ": " + t.kind + "; VEX files " + t.vexes + "; CVEs " + t.cves
                    + "; of the report missing from the VEX " + t.absent + "; not in the report " + t.extra
                    + "; without an OWASP rating " + t.missing + "; rated twice " + t.twice + "; vectors " + t.vectors
                    + "; refused by fromVector() or calculateScore() " + t.refused
                    + "; sub-scores off the level sums /8, /4, /4 " + t.subOff + " (not applicable " + t.subNa + ")"
                    + "; severity differing from OWASP's matrix on the calculator's bands with max(T, B) " + t.sevOff
                    + " (not applicable " + t.sevNa + ")"
                    + "; score differing from likelihood x max(T, B) " + t.scoreOff + " (not applicable " + t.scoreNa
                    + "); " + (f.isEmpty() ? "PASS" : "FAIL: " + String.join(", ", f)));
        }
        System.out.println(failed == 0 ? "Check4: every label passes" : "Check4: FAIL in " + failed + " of "
                + labels.size() + " labels");
        if (failed > 0) System.exit(1);
    }
}
