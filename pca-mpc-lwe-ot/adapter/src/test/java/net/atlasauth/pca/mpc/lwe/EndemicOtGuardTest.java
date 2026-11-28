package net.atlasauth.pca.mpc.lwe;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import net.atlasauth.pca.mpc.Ot;
import net.atlasauth.pca.mpc.Ot.OtRandom;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/** Size guards, constants, the pad and session-id derivations (against an independent SHA-256 model) and every refusal of the endemic OT and its lattice core. */
class EndemicOtGuardTest {
  @BeforeAll
  static void lib() {
    boolean ok = Lattice.available();
    if (Boolean.getBoolean("pca.lweot.required")) assertTrue(ok, "liblweot must load (-Dpca.lweot.lib)");
    assumeTrue(ok, "liblweot not available");
  }

  private static byte[] sha(byte[]... chunks) throws Exception {
    MessageDigest h = MessageDigest.getInstance("SHA-256");
    for (byte[] c : chunks) h.update(c);
    return h.digest();
  }

  private static byte[] t(String s) { return s.getBytes(StandardCharsets.UTF_8); }

  private static byte[] u32(long x) { return new byte[] {(byte) (x >>> 24), (byte) (x >>> 16), (byte) (x >>> 8), (byte) x}; }

  private static byte[] fill(int n, int k) { byte[] b = new byte[n]; for (int i = 0; i < n; i++) b[i] = (byte) (i * 31 + k * 7 + (i >> 3)); return b; }

  private static OtRandom rng(String seed) { return Ot.otRandom(Ot.splitMix64(new java.math.BigInteger(seed))); }

  @Test
  void theSizesAreKyber768s() {
    assertEquals(1184, Lattice.PK_BYTES);
    assertEquals(1152, Lattice.SK_BYTES);
    assertEquals(1088, Lattice.CT_BYTES);
    assertEquals(1152, Lattice.TVEC_BYTES);
    assertEquals(32, Lattice.SYM_BYTES);
    assertEquals(4096, Lattice.HASHIN_CAP);
    assertEquals(32, EndemicOt.ENDEMIC_SECRET_BYTES);
  }

  @Test
  void keygenRefusesAWrongSeedAndYieldsSizedKeys() {
    for (byte[] bad : new byte[][] {null, new byte[31], new byte[33]}) {
      assertThrows(IllegalArgumentException.class, () -> Lattice.keygen(bad));
      assertThrows(IllegalArgumentException.class, () -> Lattice.keygenFips203(bad));
    }
    for (Lattice.KeyPair k : new Lattice.KeyPair[] {Lattice.keygen(fill(32, 1)), Lattice.keygenFips203(fill(32, 1))}) {
      assertEquals(Lattice.PK_BYTES, k.publicKey().length);
      assertEquals(Lattice.SK_BYTES, k.secretKey().length);
    }
    assertArrayEquals(Lattice.keygen(fill(32, 2)).publicKey(), Lattice.keygen(fill(32, 2)).publicKey());
    assertFalse(Arrays.equals(Lattice.keygen(fill(32, 2)).publicKey(), Lattice.keygen(fill(32, 3)).publicKey()));
  }

  @Test
  void encDecRoundTripAndRefuseWrongSizes() {
    Lattice.KeyPair k = Lattice.keygen(fill(32, 4));
    byte[] msg = fill(32, 5), coins = fill(32, 6);
    byte[] ct = Lattice.enc(k.publicKey(), msg, coins);
    assertEquals(Lattice.CT_BYTES, ct.length);
    assertArrayEquals(msg, Lattice.dec(k.secretKey(), ct));
    assertArrayEquals(ct, Lattice.enc(k.publicKey(), msg, coins));
    for (byte[] bad : new byte[][] {null, new byte[Lattice.PK_BYTES - 1], new byte[Lattice.PK_BYTES + 1]}) {
      assertThrows(IllegalArgumentException.class, () -> Lattice.enc(bad, msg, coins));
    }
    for (byte[] bad : new byte[][] {null, new byte[31], new byte[33]}) {
      assertThrows(IllegalArgumentException.class, () -> Lattice.enc(k.publicKey(), bad, coins));
      assertThrows(IllegalArgumentException.class, () -> Lattice.enc(k.publicKey(), msg, bad));
    }
    for (byte[] bad : new byte[][] {null, new byte[Lattice.SK_BYTES - 1], new byte[Lattice.SK_BYTES + 1]}) {
      assertThrows(IllegalArgumentException.class, () -> Lattice.dec(bad, ct));
    }
    for (byte[] bad : new byte[][] {null, new byte[Lattice.CT_BYTES - 1], new byte[Lattice.CT_BYTES + 1]}) {
      assertThrows(IllegalArgumentException.class, () -> Lattice.dec(k.secretKey(), bad));
    }
  }

  @Test
  void ringAddAndSubAreInverseAndRefuseWrongSizes() {
    byte[] a = Lattice.hashToRing(t("a")), b = Lattice.hashToRing(t("b"));
    byte[] sum = Lattice.ringAdd(a, b);
    assertEquals(Lattice.TVEC_BYTES, sum.length);
    assertFalse(Arrays.equals(sum, a));
    assertArrayEquals(sum, Lattice.ringAdd(b, a));
    assertArrayEquals(a, Lattice.ringSub(sum, b));
    assertArrayEquals(b, Lattice.ringSub(sum, a));
    assertFalse(Arrays.equals(Lattice.ringSub(a, b), Lattice.ringSub(b, a)));
    assertArrayEquals(new byte[Lattice.TVEC_BYTES], Lattice.ringSub(a, a));
    for (byte[] bad : new byte[][] {null, new byte[Lattice.TVEC_BYTES - 1], new byte[Lattice.TVEC_BYTES + 1]}) {
      assertThrows(IllegalArgumentException.class, () -> Lattice.ringAdd(bad, b));
      assertThrows(IllegalArgumentException.class, () -> Lattice.ringAdd(a, bad));
      assertThrows(IllegalArgumentException.class, () -> Lattice.ringSub(bad, b));
      assertThrows(IllegalArgumentException.class, () -> Lattice.ringSub(a, bad));
    }
  }

  @Test
  void hashToRingIsCappedAtFourKiBAndDeterministic() {
    assertEquals(Lattice.TVEC_BYTES, Lattice.hashToRing(new byte[0]).length);
    assertEquals(Lattice.TVEC_BYTES, Lattice.hashToRing(new byte[Lattice.HASHIN_CAP]).length);
    assertThrows(IllegalArgumentException.class, () -> Lattice.hashToRing(new byte[Lattice.HASHIN_CAP + 1]));
    assertThrows(IllegalArgumentException.class, () -> Lattice.hashToRing(null));
    assertArrayEquals(Lattice.hashToRing(t("x")), Lattice.hashToRing(t("x")));
    assertFalse(Arrays.equals(Lattice.hashToRing(t("x")), Lattice.hashToRing(t("y"))));
  }

  @Test
  void sessionIdAndPadFollowTheirDerivations() throws Exception {
    byte[] rn = fill(32, 7);
    byte[] sid = EndemicOt.sessionId(rn);
    assertArrayEquals(sha(t("atlas-pca-mpc/endemic-lwe-ot-sid"), rn), sid);
    assertFalse(Arrays.equals(sid, EndemicOt.sessionId(fill(32, 8))));
    byte[] payload = fill(32, 9);
    byte[] tag = t("atlas-pca-mpc/endemic-lwe-ot-pad");
    for (int len : new int[] {0, 1, 31, 32, 33, 64, 65, 100}) {
      byte[] want = new byte[len];
      for (int ctr = 0; ctr * 32 < len; ctr++) {
        byte[] block = sha(tag, sid, u32(3), new byte[] {1}, u32(ctr), payload);
        System.arraycopy(block, 0, want, ctr * 32, Math.min(32, len - ctr * 32));
      }
      assertArrayEquals(want, EndemicOt.pad(sid, 3, 1, payload, len), "len " + len);
    }
    byte[] base = EndemicOt.pad(sid, 3, 1, payload, 32);
    assertFalse(Arrays.equals(base, EndemicOt.pad(sid, 4, 1, payload, 32)));
    assertFalse(Arrays.equals(base, EndemicOt.pad(sid, 3, 0, payload, 32)));
    assertFalse(Arrays.equals(base, EndemicOt.pad(sid, 3, 1, fill(32, 10), 32)));
    assertFalse(Arrays.equals(base, EndemicOt.pad(fill(32, 11), 3, 1, payload, 32)));
    assertArrayEquals(EndemicOt.pad(sid, 3, 0, payload, 32), EndemicOt.pad(sid, 3, 2, payload, 32), "only the low bit of the slot counts");
    assertArrayEquals(base, EndemicOt.pad(sid, 3, 3, payload, 32));
  }

  @Test
  void receiveMasksTheChoicesToABitAndKeepsItsState() {
    int[] choices = {3, 2, 1, 0, -1};
    EndemicOt.Receive rv = EndemicOt.receive(choices, rng("21"));
    assertArrayEquals(new int[] {1, 0, 1, 0, 1}, rv.state().choices());
    assertEquals(5, rv.message().points().length);
    assertEquals(5, rv.message().rhos().length);
    assertArrayEquals(EndemicOt.sessionId(rv.message().rn()), rv.state().sid());
    assertArrayEquals(rv.message().rn(), rv.state().rn());
    assertTrue(Arrays.deepEquals(rv.message().rhos(), rv.state().rhos()));
    assertEquals(5, rv.state().secretKeys().length);
    for (int i = 0; i < 5; i++) {
      assertEquals(2, rv.message().points()[i].length);
      assertEquals(Lattice.TVEC_BYTES, rv.message().points()[i][0].length);
      assertEquals(Lattice.TVEC_BYTES, rv.message().points()[i][1].length);
      assertEquals(Lattice.PK_BYTES - Lattice.TVEC_BYTES, rv.message().rhos()[i].length);
      assertEquals(Lattice.SK_BYTES, rv.state().secretKeys()[i].length);
    }
    EndemicOt.RandomResult r = EndemicOt.baseOtRandom(choices, rng("22"), null);
    for (int i = 0; i < choices.length; i++) assertArrayEquals(r.senderPads()[i][choices[i] & 1], r.recvPads()[i]);
    for (int i = 0; i < choices.length; i++) assertFalse(Arrays.equals(r.senderPads()[i][1 - (choices[i] & 1)], r.recvPads()[i]), "the other pad stays hidden");
  }

  @Test
  void theSenderRefusesEveryMalformedReceiverMessage() {
    EndemicOt.ReceiverMessage ok = EndemicOt.receive(new int[] {0, 1}, rng("31")).message();
    byte[] rn = ok.rn();
    byte[][][] pts = ok.points();
    byte[][] rhos = ok.rhos();
    OtRandom r = rng("32");
    EndemicOt.sendRandom(ok, r, null);
    assertThrows(EndemicOt.EndemicAbort.class, () -> EndemicOt.sendRandom(null, r, null));
    assertThrows(EndemicOt.EndemicAbort.class, () -> EndemicOt.sendRandom(new EndemicOt.ReceiverMessage(null, pts, rhos), r, null));
    assertThrows(EndemicOt.EndemicAbort.class, () -> EndemicOt.sendRandom(new EndemicOt.ReceiverMessage(new byte[31], pts, rhos), r, null));
    assertThrows(EndemicOt.EndemicAbort.class, () -> EndemicOt.sendRandom(new EndemicOt.ReceiverMessage(new byte[33], pts, rhos), r, null));
    assertThrows(EndemicOt.EndemicAbort.class, () -> EndemicOt.sendRandom(new EndemicOt.ReceiverMessage(rn, null, rhos), r, null));
    assertThrows(EndemicOt.EndemicAbort.class, () -> EndemicOt.sendRandom(new EndemicOt.ReceiverMessage(rn, pts, null), r, null));
    assertThrows(EndemicOt.EndemicAbort.class, () -> EndemicOt.sendRandom(new EndemicOt.ReceiverMessage(rn, new byte[][][] {pts[0]}, rhos), r, null));
    assertThrows(EndemicOt.EndemicAbort.class, () -> EndemicOt.sendRandom(new EndemicOt.ReceiverMessage(rn, pts, new byte[][] {rhos[0]}), r, null));
    for (int i = 0; i < 2; i++) {
      final int k = i;
      byte[][][] bad = new byte[][][] {pts[0].clone(), pts[1].clone()};
      bad[k] = null;
      assertThrows(EndemicOt.EndemicAbort.class, () -> EndemicOt.sendRandom(new EndemicOt.ReceiverMessage(rn, bad, rhos), r, null));
      for (byte[][] shape : new byte[][][] {new byte[][] {pts[k][0]}, new byte[][] {pts[k][0], pts[k][1], pts[k][1]},
          new byte[][] {null, pts[k][1]}, new byte[][] {pts[k][0], null}, new byte[][] {new byte[1151], pts[k][1]},
          new byte[][] {pts[k][0], new byte[1151]}, new byte[][] {new byte[1153], pts[k][1]}, new byte[][] {pts[k][0], new byte[1153]}}) {
        byte[][][] b2 = new byte[][][] {pts[0].clone(), pts[1].clone()};
        b2[k] = shape;
        assertThrows(EndemicOt.EndemicAbort.class, () -> EndemicOt.sendRandom(new EndemicOt.ReceiverMessage(rn, b2, rhos), r, null));
      }
      byte[][] rh = rhos.clone();
      rh[k] = null;
      assertThrows(EndemicOt.EndemicAbort.class, () -> EndemicOt.sendRandom(new EndemicOt.ReceiverMessage(rn, pts, rh), r, null));
      for (int len : new int[] {31, 33}) {
        byte[][] rh2 = rhos.clone();
        rh2[k] = new byte[len];
        assertThrows(EndemicOt.EndemicAbort.class, () -> EndemicOt.sendRandom(new EndemicOt.ReceiverMessage(rn, pts, rh2), r, null));
      }
    }
  }

  @Test
  void recoveryRefusesEveryMalformedSenderMessage() {
    int[] choices = {0, 1};
    EndemicOt.Receive rv = EndemicOt.receive(choices, rng("41"));
    EndemicOt.SenderMessage sm = EndemicOt.sendRandom(rv.message(), rng("42"), null);
    byte[][][] cts = sm.ciphertexts();
    assertEquals(2, EndemicOt.recoverRandom(rv.state(), sm).length);
    assertThrows(EndemicOt.EndemicAbort.class, () -> EndemicOt.recoverRandom(rv.state(), null));
    assertThrows(EndemicOt.EndemicAbort.class, () -> EndemicOt.recoverRandom(rv.state(), new EndemicOt.SenderMessage(null, null)));
    assertThrows(EndemicOt.EndemicAbort.class, () -> EndemicOt.recoverRandom(rv.state(), new EndemicOt.SenderMessage(new byte[][][] {cts[0]}, null)));
    assertThrows(EndemicOt.EndemicAbort.class, () -> EndemicOt.recoverRandom(rv.state(), new EndemicOt.SenderMessage(new byte[][][] {cts[0], cts[1], cts[1]}, null)));
    for (int i = 0; i < 2; i++) {
      final int k = i;
      for (byte[][] shape : new byte[][][] {null, new byte[][] {cts[k][0]}, new byte[][] {cts[k][0], cts[k][1], cts[k][1]},
          new byte[][] {null, cts[k][1]}, new byte[][] {cts[k][0], null}, new byte[][] {new byte[1087], cts[k][1]},
          new byte[][] {cts[k][0], new byte[1087]}, new byte[][] {new byte[1089], cts[k][1]}, new byte[][] {cts[k][0], new byte[1089]}}) {
        byte[][][] bad = new byte[][][] {cts[0].clone(), cts[1].clone()};
        bad[k] = shape;
        assertThrows(EndemicOt.EndemicAbort.class, () -> EndemicOt.recoverRandom(rv.state(), new EndemicOt.SenderMessage(bad, null)));
      }
    }
  }

  @Test
  void chosenMessageTransferDeliversTheChosenMessageOfAnyLength() {
    byte[][][] msgs = {{fill(5, 1), fill(5, 2)}, {fill(70, 3), fill(70, 4)}, {fill(32, 5), fill(32, 6)}, {new byte[0], new byte[0]}};
    int[] choices = {1, 0, 3, 2};
    EndemicOt.Result r = EndemicOt.baseOT(msgs, choices, rng("51"), null);
    for (int i = 0; i < msgs.length; i++) assertArrayEquals(msgs[i][choices[i] & 1], r.received()[i]);
    EndemicOt.Transcript tr = r.transcript();
    assertEquals(4, tr.points().length);
    assertEquals(4, tr.rhos().length);
    assertEquals(32, tr.rn().length);
    for (int i = 0; i < 4; i++) {
      assertEquals(2, tr.ciphertexts()[i].length);
      assertEquals(Lattice.CT_BYTES, tr.ciphertexts()[i][0].length);
      assertEquals(msgs[i][0].length, tr.encrypted()[i][0].length);
      assertEquals(msgs[i][1].length, tr.encrypted()[i][1].length);
      assertEquals(32, tr.commitments()[i][0].length);
      assertEquals(32, tr.commitments()[i][1].length);
      assertFalse(Arrays.equals(tr.commitments()[i][0], tr.commitments()[i][1]));
    }
    // the base-OT seam is the same transfer
    byte[][] viaSeam = EndemicOt.withEndemicBaseOt().run(msgs, choices, rng("52"));
    for (int i = 0; i < msgs.length; i++) assertArrayEquals(msgs[i][choices[i] & 1], viaSeam[i]);
    assertNotNull(EndemicOt.withEndemicBaseOt());
  }

  @Test
  void chosenMessageTransferRefusesBadShapesAndAbortsOnATamperedChosenSlot() {
    byte[][][] msgs = {{fill(8, 1), fill(8, 2)}, {fill(8, 3), fill(8, 4)}};
    assertThrows(IllegalArgumentException.class, () -> EndemicOt.baseOT(msgs, new int[] {0}, rng("61"), null));
    assertThrows(IllegalArgumentException.class, () -> EndemicOt.baseOT(msgs, new int[] {0, 1, 0}, rng("61"), null));
    assertThrows(IllegalArgumentException.class, () -> EndemicOt.baseOT(new byte[][][] {{fill(8, 1), fill(9, 2)}}, new int[] {0}, rng("61"), null));
    // tampering the chosen slot aborts (the commitment fails); the other slot is never opened
    int[] choices = {1, 0};
    assertThrows(EndemicOt.EndemicAbort.class, () -> EndemicOt.baseOT(msgs, choices, rng("62"), e -> e[0][1][0] ^= 1));
    assertThrows(EndemicOt.EndemicAbort.class, () -> EndemicOt.baseOT(msgs, choices, rng("62"), e -> e[1][0][7] ^= 0x80));
    EndemicOt.Result r = EndemicOt.baseOT(msgs, choices, rng("62"), e -> { e[0][0][0] ^= 1; e[1][1][0] ^= 1; });
    assertArrayEquals(msgs[0][1], r.received()[0]);
    assertArrayEquals(msgs[1][0], r.received()[1]);
  }
}
