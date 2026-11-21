package net.atlasauth.pca.fndsa;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.Issue;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.Keys;
import net.atlasauth.pca.Pca;
import net.atlasauth.pca.Pq;
import net.atlasauth.pca.ProducerOps;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * FN-DSA signing parity and end to end PCActn verification over libfndsa: the fn-dsa cases of the producer vectors byte for byte, the
 * shared PCActn fixture signed through Issue.signPCActn and verified through Pca.verifyPcactn, and the no-backend refusals. ATLAS_PCA_LIBFNDSA
 * selects the library; ATLAS_PCA_LIBFNDSA_REQUIRED=1 turns a missing library into a failure.
 */
class NativeFnDsaE2eTest {
  private static boolean native_;

  @BeforeEach
  void backend() {
    FnDsa.resetFalconBackend();
    native_ = NativeFnDsa.available();
    if ("1".equals(System.getenv("ATLAS_PCA_LIBFNDSA_REQUIRED"))) assertTrue(native_, "libfndsa must load (ATLAS_PCA_LIBFNDSA)");
  }

  @AfterEach
  void reset() { FnDsa.resetFalconBackend(); }

  private static void register() {
    assumeTrue(native_, "libfndsa not available");
    NativeFnDsa.register();
  }

  @SuppressWarnings("unchecked")
  private static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }

  @SuppressWarnings("unchecked")
  private static List<Object> l(Object o) { return (List<Object>) o; }

  private static Map<String, Object> load(String p) throws Exception { return m(Json.parseLenient(Files.readString(Path.of(p)))); }

  private static byte[] seed(String label) throws Exception {
    return MessageDigest.getInstance("SHA-256").digest(("atlas-pca-conformance/" + label).getBytes(StandardCharsets.UTF_8));
  }

  private static Pq.Prim prim(String alg) { return "fn-dsa-512".equals(alg) ? Pq.Prim.FN_DSA_512 : Pq.Prim.FN_DSA_1024; }

  @Test void producerVectorsFnDsaByteExact() throws Exception {
    register();
    Map<String, Object> doc = load("../../conformance/producer-pq-vectors.json");
    ProducerOps ops = new ProducerOps(m(doc.get("ed_keys")), m(doc.get("pq_keys")));
    int n = 0;
    for (Object c : l(doc.get("cases"))) {
      Map<String, Object> v = m(c);
      String name = (String) v.get("name");
      if (!name.contains("fn-dsa")) continue;
      assertEquals(Json.canonicalize(v.get("expect")), Json.canonicalize(ops.run((String) v.get("op"), m(v.get("args")))), name);
      n++;
    }
    assertTrue(n >= 16, "the fn-dsa producer vectors shrank: " + n);
  }

  @Test void fixtureSignsByteExactAndEveryCaseVerifies() throws Exception {
    register();
    int signed = 0;
    for (Object c : l(load("test-data/ref-fndsa-pcactn.json").get("cases"))) {
      Map<String, Object> v = m(c);
      String name = (String) v.get("name"), alg = (String) v.get("alg");
      if (v.get("body") != null) {
        Map<String, String> lab = new java.util.HashMap<>();
        m(v.get("key_labels")).forEach((k, x) -> lab.put(k, (String) x));
        try {
          Keys.PqKey pq = Keys.pqFromSeed(prim(alg), seed(lab.get("fndsa_keygen")), seed(lab.get("fndsa_sign_seed")));
          assertEquals(v.get("pq_pk"), pq.pkB64u(), name);
          Map<String, Object> got = Issue.signPCActn(m(v.get("body")), Keys.suite(alg, Keys.edFromSeed(seed(lab.get("agent_ed25519"))), pq));
          assertEquals(Json.canonicalize(v.get("pcactn")), Json.canonicalize(got), name);
          signed++;
        } catch (Exception e) { throw new AssertionError(name + ": " + e, e); }
      }
      Pca.Verdict d = Pca.verifyPcactn(v.get("pcactn"), m(v.get("grant")), Json.asLong(v.get("now_epoch")), (String) v.get("audience"), null, null, null, null, Pca.PlanRoots.SKIP);
      assertEquals(Boolean.TRUE.equals(v.get("expect_allow")), d.allow, name + ": " + d.reason);
    }
    assertEquals(2, signed);
  }

  @Test void noBackendDeniesEveryCaseAndRefusesToSign() throws Exception {
    assertFalse(FnDsa.hasBackend());
    for (Object c : l(load("test-data/ref-fndsa-pcactn.json").get("cases"))) {
      Map<String, Object> v = m(c);
      Pca.Verdict d = Pca.verifyPcactn(v.get("pcactn"), m(v.get("grant")), Json.asLong(v.get("now_epoch")), (String) v.get("audience"), null, null, null, null, Pca.PlanRoots.SKIP);
      String name = (String) v.get("name");
      assertFalse(d.allow, name);
      if (name.endsWith("/valid")) assertTrue(d.reason.contains("unsupported_suite"), d.reason);
    }
    IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> Keys.pqFromSeed(Pq.Prim.FN_DSA_512, new byte[32], new byte[32]));
    assertEquals("unsupported_suite: fn-dsa-512", e.getMessage());
    e = assertThrows(IllegalArgumentException.class, () -> Keys.suite("fn-dsa-1024", null, null));
    assertEquals("unsupported_suite: fn-dsa-1024", e.getMessage());
  }
}
