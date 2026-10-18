/* KODA's data-only, bounded subprocess adapter for java.util.regex.Pattern. */
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

public final class RegexMatcher {
    private static String decode(String value) {
        return new String(Base64.getDecoder().decode(value), StandardCharsets.UTF_8);
    }

    private static String encode(String value) {
        return Base64.getEncoder().encodeToString(value.getBytes(StandardCharsets.UTF_8));
    }

    private static String legacy(String value) {
        String pattern = value.replace("*", ".*").replace("..*", ".*");
        if (!pattern.startsWith("^") && !pattern.startsWith(".*")) pattern = ".*" + pattern;
        if (!pattern.endsWith("$") && !pattern.endsWith(".*")) pattern += ".*";
        return pattern;
    }

    public static void main(String[] args) {
        int index = 0;
        try {
            BufferedReader input = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
            String header = input.readLine();
            if (!"KODA_REGEX_V1\tE".equals(header) && !"KODA_REGEX_V1\tV".equals(header)) throw new IllegalArgumentException("Invalid protocol");
            boolean validateOnly = header.endsWith("V");
            ArrayList<Boolean> matches = new ArrayList<>();
            Map<String, Pattern> compiled = new HashMap<>();
            String line;
            long inputChars = header.length() + 1;
            while ((line = input.readLine()) != null) {
                if (++index > 100_000 || (inputChars += line.length() + 1) > 4 * 1024 * 1024) throw new IllegalArgumentException("Input limit exceeded");
                String[] fields = line.split("\t", -1);
                if (fields.length != 3 || (!fields[0].equals("L") && !fields[0].equals("R"))) throw new IllegalArgumentException("Invalid request");
                String source = decode(fields[1]);
                if (source.codePointCount(0, source.length()) > 2048) throw new IllegalArgumentException("Pattern limit exceeded");
                String expression = fields[0].equals("L") ? legacy(source) : source;
                Pattern pattern = compiled.get(expression);
                if (pattern == null) {
                    if (compiled.size() >= 200) throw new IllegalArgumentException("Pattern count limit exceeded");
                    pattern = Pattern.compile(expression);
                    compiled.put(expression, pattern);
                }
                String value = null;
                if (!fields[2].equals("N")) {
                    if (!fields[2].startsWith("S")) throw new IllegalArgumentException("Invalid text marker");
                    value = decode(fields[2].substring(1));
                    if (value.getBytes(StandardCharsets.UTF_8).length > 64 * 1024) throw new IllegalArgumentException("Text limit exceeded");
                }
                matches.add(!validateOnly && value != null && pattern.matcher(value).matches());
            }
            StringBuilder output = new StringBuilder("OK\t" + matches.size() + "\n");
            for (boolean match : matches) output.append(match ? "1\n" : "0\n");
            System.out.print(output);
        } catch (PatternSyntaxException e) {
            System.out.print("SYNTAX\t" + index + "\t" + encode(e.getDescription()) + "\n");
        } catch (Throwable e) {
            // Stack exhaustion and other evaluation failures never become false.
            System.out.print("ERROR\t" + encode(e.getClass().getSimpleName()) + "\n");
        }
    }
}
