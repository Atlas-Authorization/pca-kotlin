package net.atlasauth.pca.mpc.lwe;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import net.atlasauth.pca.mpc.NetCodec;
import net.atlasauth.pca.mpc.NetWire.NetAbort;
import net.atlasauth.pca.mpc.Ot;
import net.atlasauth.pca.mpc.net.Certs;
import net.atlasauth.pca.mpc.net.LaunchLocal;
import net.atlasauth.pca.mpc.net.Mesh;
import net.atlasauth.pca.mpc.net.OtNet;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * The endemic-LWE base OT over a real two-node mutual-TLS mesh on loopback: the honest sender/receiver pair, and each abort and verdict path
 * of both roles driven by a hand-written peer. Node 0 is the sender and node 1 the receiver, as the core party program wires them.
 */
class EndemicOtMeshTest {
  @BeforeAll
  static void lib() {
    boolean ok = Lattice.available();
    if (Boolean.getBoolean("pca.lweot.required")) assertTrue(ok, "liblweot must load (-Dpca.lweot.lib)");
    assumeTrue(ok, "liblweot not available");
  }

  private static Mesh[] pair() throws Exception {
    LaunchLocal.Options o = new LaunchLocal.Options();
    o.recvTimeoutMs = 20_000;
    o.connectTimeoutMs = 30_000;
    return LaunchLocal.bind(o, 2, 2, false, identities()).meshes();
  }

  private static Certs.Identity[] ids;

  /** One pair of throwaway identities for the class: each openssl run costs more than a whole transfer. */
  private static synchronized Certs.Identity[] identities() {
    if (ids == null) ids = new Certs.Identity[] {Certs.generate("lwe-node-0"), Certs.generate("lwe-node-1")};
    return ids;
  }

  private static <T> T[] both(Callable<T> a, Callable<T> b, Mesh[] m, T[] out) throws Exception {
    ExecutorService ex = Executors.newFixedThreadPool(2);
    try {
      Future<T> fa = ex.submit(() -> { m[0].connect(); return a.call(); });
      Future<T> fb = ex.submit(() -> { m[1].connect(); return b.call(); });
      out[0] = get(fa);
      out[1] = get(fb);
      return out;
    } finally {
      for (Mesh x : m) x.kill();
      ex.shutdownNow();
    }
  }

  private static <T> T get(Future<T> f) throws Exception {
    try {
      return f.get(90, TimeUnit.SECONDS);
    } catch (java.util.concurrent.ExecutionException e) {
      if (e.getCause() instanceof Exception) throw (Exception) e.getCause();
      throw e;
    }
  }

  private static final String Z32 = NetCodec.b64(new byte[32]);

  /** The sender's view of a hand-written receiver peer: the receiver round is real, the verify message is the argument. */
  private static OtNet.Result senderAgainst(Object verify, boolean realRound, Object recvPayload, boolean[] doneMatched) throws Exception {
    Mesh[] m = pair();
    OtNet.Result[] res = new OtNet.Result[2];
    Callable<OtNet.Result> sender = () -> EndemicOtNet.runOtSender(m[0], 1, 2);
    Callable<OtNet.Result> peer = () -> {
      Object payload = recvPayload;
      EndemicOt.Receive rv = null;
      if (realRound) {
        rv = EndemicOt.receive(new int[] {1, 0}, Ot.secureOtRandom());
        Map<String, Object> o = new LinkedHashMap<>();
        o.put("rn", NetCodec.b64(rv.message().rn()));
        List<Object> pts = new ArrayList<>(), rhos = new ArrayList<>();
        for (byte[][] p : rv.message().points()) pts.add(List.of(NetCodec.b64(p[0]), NetCodec.b64(p[1])));
        for (byte[] r : rv.message().rhos()) rhos.add(NetCodec.b64(r));
        o.put("points", pts);
        o.put("rhos", rhos);
        payload = o;
      }
      m[1].send(0, "ot-recv", payload);
      if (!realRound) return null;
      m[1].recv(0, "ot-ct");
      m[1].send(0, "ot-verify", verify);
      Object d = m[1].recv(0, "ot-done");
      doneMatched[0] = Boolean.TRUE.equals(((Map<?, ?>) d).get("matched"));
      return null;
    };
    both(sender, peer, m, res);
    return res[0];
  }

  @Test
  void honestPairAgreeAndReportTheirRoles() throws Exception {
    Mesh[] m = pair();
    OtNet.Result[] r = both(() -> EndemicOtNet.runOtSender(m[0], 1, 3), () -> EndemicOtNet.runOtReceiver(m[1], 0, 3), m, new OtNet.Result[2]);
    assertEquals("lwe", r[0].kind());
    assertEquals("lwe", r[1].kind());
    assertEquals("sender", r[0].role());
    assertEquals("receiver", r[1].role());
    assertEquals(3, r[0].count());
    assertEquals(3, r[1].count());
    assertTrue(r[0].matched(), "the sender verified every pad hash");
    assertTrue(r[1].matched(), "the receiver was told the pads matched");
    assertEquals(64, r[0].padDigest().length());
    assertEquals(64, r[1].padDigest().length());
    // the sender digests BOTH pads of every transfer, the receiver only the chosen one
    assertNotEquals(r[0].padDigest(), r[1].padDigest());
  }

  @Test
  void aMalformedReceiverMessageAbortsTheSender() throws Exception {
    Exception e = assertThrows(Exception.class, () -> senderAgainst(null, false, "not a map", new boolean[1]));
    assertTrue(e instanceof NetAbort, String.valueOf(e));
    assertEquals("malformed", ((NetAbort) e).kind);
  }

  @Test
  void aWrongSizedPointIsRefusedByTheSenderAsAnLweAbort() throws Exception {
    Map<String, Object> o = new LinkedHashMap<>();
    o.put("rn", Z32);
    o.put("points", List.of(List.of(Z32, Z32), List.of(Z32, Z32)));
    o.put("rhos", List.of(Z32, Z32));
    Exception e = assertThrows(Exception.class, () -> senderAgainst(null, false, o, new boolean[1]));
    assertTrue(e instanceof NetAbort, String.valueOf(e));
    assertEquals("malformed", ((NetAbort) e).kind);
    assertTrue(e.getMessage().contains("lwe sender: "), e.getMessage());
    assertEquals(Integer.valueOf(1), ((NetAbort) e).blamed);
    assertEquals(0, ((NetAbort) e).reporter);
  }

  @Test
  void aMalformedVerifyMessageAbortsTheSender() throws Exception {
    boolean[] done = new boolean[1];
    Exception e = assertThrows(Exception.class, () -> senderAgainst("nope", true, null, done));
    assertTrue(e instanceof NetAbort, String.valueOf(e));
    assertEquals("malformed", ((NetAbort) e).kind);
    assertTrue(e.getMessage().contains("ot-verify"), e.getMessage());
  }

  @Test
  void aWrongPadHashOrChoiceBitMakesTheSenderReportNoMatch() throws Exception {
    String zeroHash = HexFormat.of().formatHex(new byte[32]);
    Map<String, Object> badHash = new LinkedHashMap<>();
    badHash.put("choices", List.of(1, 0));
    badHash.put("padHashes", List.of(zeroHash, zeroHash));
    boolean[] done = {true};
    OtNet.Result r = senderAgainst(badHash, true, null, done);
    assertFalse(r.matched());
    assertFalse(done[0], "the sender tells the peer the pads did not match");
    Map<String, Object> badBit = new LinkedHashMap<>();
    badBit.put("choices", List.of(2, 0));
    badBit.put("padHashes", List.of(zeroHash, zeroHash));
    done[0] = true;
    assertFalse(senderAgainst(badBit, true, null, done).matched());
    assertFalse(done[0]);
  }

  /** The receiver's view of a hand-written sender peer, which answers the receiver round with the given 'ot-ct' payload and 'ot-done' verdict. */
  private static OtNet.Result receiverAgainst(Object ct, Object done) throws Exception {
    Mesh[] m = pair();
    OtNet.Result[] res = new OtNet.Result[2];
    Callable<OtNet.Result> sender = () -> {
      Object rm = m[0].recv(1, "ot-recv");
      assertTrue(rm instanceof Map);
      m[0].send(1, "ot-ct", ct);
      if (done != null) {
        m[0].recv(1, "ot-verify");
        m[0].send(1, "ot-done", done);
      }
      return null;
    };
    both(sender, () -> EndemicOtNet.runOtReceiver(m[1], 0, 2), m, res);
    return res[1];
  }

  private static List<Object> okPair() { return List.of(NetCodec.b64(new byte[1088]), NetCodec.b64(new byte[1088])); }

  @Test
  void aMalformedCiphertextArrayAbortsTheReceiver() throws Exception {
    for (Object bad : new Object[] {"x", List.of(okPair()), List.of(okPair(), "x"), List.of(okPair(), List.of(Z32))}) {
      Exception e = assertThrows(Exception.class, () -> receiverAgainst(bad, null), String.valueOf(bad));
      assertTrue(e instanceof NetAbort, String.valueOf(e));
      assertEquals("malformed", ((NetAbort) e).kind);
      assertEquals(Integer.valueOf(0), ((NetAbort) e).blamed);
      assertEquals(1, ((NetAbort) e).reporter);
    }
  }

  @Test
  void aWrongSizedCiphertextAbortsTheReceiver() throws Exception {
    Exception e = assertThrows(Exception.class, () -> receiverAgainst(List.of(okPair(), List.of(Z32, Z32)), null));
    assertTrue(e instanceof NetAbort, String.valueOf(e));
    assertEquals("malformed", ((NetAbort) e).kind);
    assertTrue(e.getMessage().contains("ot-ct"), e.getMessage());
  }

  @Test
  void theReceiverReportsTheSendersVerdict() throws Exception {
    Map<String, Object> yes = new LinkedHashMap<>(), no = new LinkedHashMap<>(), junk = new LinkedHashMap<>();
    yes.put("matched", true);
    no.put("matched", false);
    junk.put("matched", "true");
    assertTrue(receiverAgainst(okPair2(), yes).matched());
    assertFalse(receiverAgainst(okPair2(), no).matched());
    assertFalse(receiverAgainst(okPair2(), junk).matched());
    assertFalse(receiverAgainst(okPair2(), "matched").matched());
  }

  /** Two well-formed (decryptable, garbage-message) ciphertext pairs: the zero ciphertext decrypts to some message, which is all the receiver needs. */
  private static List<Object> okPair2() { return List.of(okPair(), okPair()); }
}
