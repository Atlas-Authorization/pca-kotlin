package net.atlasauth.pca.mpc.lwe;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import java.util.zip.GZIPInputStream;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.Keys;
import net.atlasauth.pca.mpc.Ot;
import net.atlasauth.pca.mpc.Ot.OtRandom;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * Replays the TypeScript-reference corpus (test-data/ref-mpc-endemic.json.gz) through the native endemic OT over liblweot. Bytes are
 * {"$bytes": b64url}; {"$throws": ...} means the native must throw. Run with -Dpca.lweot.lib=... (-Dpca.lweot.required=true fails instead of skipping).
 */
class EndemicOtDiffTest {
  private static final String MOD = "ref-mpc-endemic";

  @BeforeAll
  static void lib() {
    boolean ok = Lattice.available();
    if (Boolean.getBoolean("pca.lweot.required")) assertTrue(ok, "liblweot must load (-Dpca.lweot.lib)");
    assumeTrue(ok, "liblweot not available");
  }

  interface Fn { Object apply(List<?> args) throws Exception; }

  @SuppressWarnings("unchecked")
  static void each(String fn, Fn f) throws Exception {
    List<Map<String, Object>> cases = new ArrayList<>();
    String head = "{\"fn\":" + Json.canonicalize(fn) + ",";
    try (BufferedReader in = new BufferedReader(new InputStreamReader(new GZIPInputStream(Files.newInputStream(Path.of("test-data/" + MOD + ".json.gz"))), StandardCharsets.UTF_8))) {
      for (String line; (line = in.readLine()) != null; ) {
        if (!line.startsWith(head)) continue;
        if (line.endsWith(",")) line = line.substring(0, line.length() - 1);
        cases.add((Map<String, Object>) Json.parseLenient(line));
      }
    }
    assertFalse(cases.isEmpty(), "no oracle cases for " + fn);
    List<String> bad = new ArrayList<>();
    for (Map<String, Object> c : cases) {
      Object want = c.get("out");
      boolean wantThrow = want instanceof Map && ((Map<String, Object>) want).containsKey("$throws");
      Object got = null;
      Throwable err = null;
      try { got = f.apply((List<?>) c.get("args")); } catch (Throwable t) { err = t; }
      if (wantThrow) {
        if (err == null) bad.add(c.get("name") + ": want a throw, got " + Json.canonicalize(got));
      } else if (err != null) {
        bad.add(c.get("name") + ": unexpected " + err);
      } else if (!Json.canonicalize(want).equals(Json.canonicalize(got))) {
        bad.add(c.get("name") + "\n  want " + Json.canonicalize(want) + "\n  got  " + Json.canonicalize(got));
      }
    }
    assertTrue(bad.isEmpty(), bad.size() + " divergent case(s) of " + fn + ":\n" + String.join("\n", bad.subList(0, Math.min(bad.size(), 20))));
  }

  @SuppressWarnings("unchecked")
  static byte[] by(Object o) { return Keys.unb64u((String) ((Map<String, Object>) o).get("$bytes")); }

  static Map<String, Object> bytesJson(byte[] b) { Map<String, Object> m = new LinkedHashMap<>(); m.put("$bytes", Keys.b64u(b)); return m; }

  static List<Object> J(byte[][] a) { List<Object> o = new ArrayList<>(); for (byte[] x : a) o.add(bytesJson(x)); return o; }

  static List<Object> JJ(byte[][][] a) { List<Object> o = new ArrayList<>(); for (byte[][] x : a) o.add(J(x)); return o; }

  /** The receiver key seed for a label, as the generator derives it: sha256("atlas-pca-conformance/" + label). */
  static byte[] seed(Object label) {
    try { return MessageDigest.getInstance("SHA-256").digest(("atlas-pca-conformance/" + label).getBytes(StandardCharsets.UTF_8)); }
    catch (Exception e) { throw new IllegalStateException(e); }
  }

  static OtRandom orng(Object s) { return Ot.otRandom(Ot.splitMix64(new BigInteger((String) s))); }

  static int[] ints(Object o) {
    List<?> l = (List<?>) o;
    int[] r = new int[l.size()];
    for (int i = 0; i < r.length; i++) r[i] = Integer.parseInt(l.get(i).toString());
    return r;
  }

  static byte[][][] pairs(Object o) {
    List<?> l = (List<?>) o;
    byte[][][] r = new byte[l.size()][][];
    for (int i = 0; i < r.length; i++) r[i] = new byte[][] {by(((List<?>) l.get(i)).get(0)), by(((List<?>) l.get(i)).get(1))};
    return r;
  }

  private static byte[] flip(byte[] b) { byte[] o = b.clone(); for (int i = 0; i < o.length; i++) o[i] ^= 1; return o; }

  private static byte[] fill(int n, int k) { byte[] b = new byte[n]; for (int i = 0; i < n; i++) b[i] = (byte) (i * 31 + k * 7 + (i >> 3)); return b; }

  // ---- the lattice core ----
  @Test void lweKeygenFips() throws Exception {
    each("lweKeygenFips", a -> {
      Lattice.KeyPair k = Lattice.keygenFips203(seed(a.get(0)));
      Map<String, Object> o = new LinkedHashMap<>();
      o.put("pk", bytesJson(k.publicKey()));
      o.put("skSha256", HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(k.secretKey())));
      return o;
    });
  }

  @Test void lweKeygen() throws Exception {
    each("lweKeygen", a -> {
      Lattice.KeyPair k = Lattice.keygen(seed(a.get(0)));
      Map<String, Object> o = new LinkedHashMap<>();
      o.put("pk", bytesJson(k.publicKey()));
      o.put("skSha256", HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(k.secretKey())));
      return o;
    });
  }

  @Test void lweEnc() throws Exception { each("lweEnc", a -> bytesJson(Lattice.enc(Lattice.keygen(seed(a.get(0))).publicKey(), by(a.get(1)), by(a.get(2))))); }

  @Test void lweDec() throws Exception { each("lweDec", a -> bytesJson(Lattice.dec(Lattice.keygen(seed(a.get(0))).secretKey(), by(a.get(1))))); }

  @Test void lweRing() throws Exception {
    each("lweRing", a -> bytesJson("add".equals(a.get(0)) ? Lattice.ringAdd(by(a.get(1)), by(a.get(2))) : Lattice.ringSub(by(a.get(1)), by(a.get(2)))));
  }

  @Test void lweHash() throws Exception { each("lweHash", a -> bytesJson(Lattice.hashToRing(by(a.get(0))))); }

  // ---- the protocol ----
  @Test void randomOt() throws Exception {
    each("randomOt", a -> {
      EndemicOt.Receive rv = EndemicOt.receive(ints(a.get(0)), orng(a.get(1)));
      EndemicOt.SenderMessage sm = EndemicOt.sendRandom(rv.message(), orng(a.get(2)), null);
      Map<String, Object> o = new LinkedHashMap<>();
      o.put("rn", bytesJson(rv.message().rn()));
      o.put("points", JJ(rv.message().points()));
      o.put("rhos", J(rv.message().rhos()));
      o.put("ciphertexts", JJ(sm.ciphertexts()));
      o.put("senderPads", JJ(sm.senderPads()));
      o.put("recvPads", J(EndemicOt.recoverRandom(rv.state(), sm)));
      return o;
    });
  }

  @Test void randomOtTamper() throws Exception {
    each("randomOtTamper", a -> {
      EndemicOt.Receive rv = EndemicOt.receive(ints(a.get(0)), orng(a.get(1)));
      EndemicOt.SenderMessage sm = EndemicOt.sendRandom(rv.message(), orng(a.get(2)), c -> c[0][0] = Arrays.copyOf(c[0][0], 1087));
      return J(EndemicOt.recoverRandom(rv.state(), sm));
    });
  }

  @Test void baseOt() throws Exception {
    each("baseOt", a -> {
      int[] choices = ints(a.get(1));
      var one = orng(a.get(2)); // one generator serves the receiver and then the sender, as the reference does
      String t = (String) a.get(3);
      Consumer<byte[][][]> tamper = null;
      if (t.equals("enc")) tamper = e -> e[0][0] = flip(e[0][0]);
      if (t.equals("encChosen")) tamper = e -> e[0][choices[0] & 1] = flip(e[0][choices[0] & 1]);
      EndemicOt.Result r = EndemicOt.baseOT(pairs(a.get(0)), choices, one, one, tamper);
      Map<String, Object> o = new LinkedHashMap<>();
      o.put("received", J(r.received()));
      o.put("ciphertexts", JJ(r.transcript().ciphertexts()));
      o.put("encrypted", JJ(r.transcript().encrypted()));
      o.put("commitments", JJ(r.transcript().commitments()));
      return o;
    });
  }

  @Test void baseOtRandomIsTheThreeRoundsOnOneStream() {
    int[] choices = {0, 1, 1, 0};
    EndemicOt.RandomResult r = EndemicOt.baseOtRandom(choices, orng("9"), null);
    OtRandom one = orng("9");
    EndemicOt.Receive rv = EndemicOt.receive(choices, one);
    EndemicOt.SenderMessage sm = EndemicOt.sendRandom(rv.message(), one, null);
    byte[][] rec = EndemicOt.recoverRandom(rv.state(), sm);
    assertTrue(Arrays.deepEquals(sm.senderPads(), r.senderPads()));
    assertTrue(Arrays.deepEquals(rec, r.recvPads()));
    assertTrue(Arrays.equals(rv.state().sid(), r.sid()));
    for (int i = 0; i < choices.length; i++) assertTrue(Arrays.equals(r.senderPads()[i][choices[i]], r.recvPads()[i])); // the receiver learns exactly the chosen pad
  }

  @Test void sendMalformed() throws Exception {
    each("sendMalformed", a -> {
      String kind = (String) a.get(0);
      EndemicOt.ReceiverMessage m = EndemicOt.receive(new int[] {0, 1}, orng("77")).message();
      byte[] rn = m.rn();
      byte[][][] points = new byte[][][] {m.points()[0].clone(), m.points()[1].clone()};
      byte[][] rhos = m.rhos().clone();
      if (kind.equals("nonce")) rn = fill(31, 1);
      if (kind.equals("count")) rhos = Arrays.copyOfRange(rhos, 1, rhos.length);
      if (kind.equals("point")) points[1][0] = fill(1151, 1);
      if (kind.equals("rho")) rhos[0] = fill(33, 1);
      return EndemicOt.sendRandom(new EndemicOt.ReceiverMessage(rn, points, rhos), orng("78"), null).ciphertexts().length;
    });
  }
}
