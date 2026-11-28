package net.atlasauth.pca.mpc.lwe;

import net.atlasauth.pca.Json;

import static net.atlasauth.pca.mpc.lwe.Lattice.CT_BYTES;
import static net.atlasauth.pca.mpc.lwe.Lattice.PK_BYTES;
import static net.atlasauth.pca.mpc.lwe.Lattice.SYM_BYTES;
import static net.atlasauth.pca.mpc.lwe.Lattice.TVEC_BYTES;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.function.Consumer;
import net.atlasauth.pca.mpc.Ot.BaseOtFn;
import net.atlasauth.pca.mpc.Ot.OtRandom;

/**
 * The post-quantum, maliciously-secure endemic base OT (Masny-Rindal over Module-LWE, Kyber-768 K-PKE), the TypeScript package's recommended base
 * OT. The receiver places a real key's offset-by-oracle point at its choice slot and a uniform ring vector at the other, so the sender's effective
 * key for the other slot is uniform and its ciphertext is unrecoverable; the chosen-message form pads and commits each message and aborts on any
 * inconsistency. All lattice work is {@link Lattice} (the audited pqc_kyber through liblweot); this class hashes, xors and marshals bytes.
 * The receiver's real key pair is the FIPS 203 K-PKE.KeyGen(d), the derivation the reference uses, so every receiver message matches it byte for byte.
 */
public final class EndemicOt {
  private EndemicOt() {}

  private static final byte[] TAG_SID = utf8("atlas-pca-mpc/endemic-lwe-ot-sid");
  private static final byte[] TAG_HPK = utf8("atlas-pca-mpc/endemic-lwe-ot-hpk");
  private static final byte[] TAG_N = utf8("atlas-pca-mpc/endemic-lwe-ot-N");
  private static final byte[] TAG_PAD = utf8("atlas-pca-mpc/endemic-lwe-ot-pad");
  private static final byte[] TAG_COMMIT = utf8("atlas-pca-mpc/endemic-lwe-ot-commit");

  /** Byte length of a derived random-OT shared secret (a K-PKE payload). */
  public static final int ENDEMIC_SECRET_BYTES = SYM_BYTES;

  /** The endemic base OT aborted: malformed input, or a sender ciphertext failing its commitment. */
  public static final class EndemicAbort extends RuntimeException {
    public EndemicAbort(String message) { super(message); }
  }

  public record ReceiverMessage(byte[] rn, byte[][][] points, byte[][] rhos) {}

  public record ReceiverState(int[] choices, byte[][] secretKeys, byte[][] rhos, byte[] rn, byte[] sid) {}

  public record Receive(ReceiverMessage message, ReceiverState state) {}

  public record SenderMessage(byte[][][] ciphertexts, byte[][][] senderPads) {}

  public record Transcript(byte[] rn, byte[][][] points, byte[][] rhos, byte[][][] ciphertexts, byte[][][] encrypted, byte[][][] commitments) {}

  public record Result(byte[][] received, Transcript transcript) {}

  private static byte[] utf8(String s) { return Json.utf8(s); }

  private static byte[] sha256(byte[]... chunks) {
    try {
      MessageDigest h = MessageDigest.getInstance("SHA-256");
      for (byte[] c : chunks) h.update(c);
      return h.digest();
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException(e);
    }
  }

  private static byte[] u32(long x) { return new byte[] {(byte) (x >>> 24), (byte) (x >>> 16), (byte) (x >>> 8), (byte) x}; }

  private static byte[] concat(byte[]... parts) {
    int n = 0;
    for (byte[] p : parts) n += p.length;
    byte[] out = new byte[n];
    int o = 0;
    for (byte[] p : parts) { System.arraycopy(p, 0, out, o, p.length); o += p.length; }
    return out;
  }

  private static byte[] xor(byte[] a, byte[] b) {
    if (a.length != b.length) throw new IllegalArgumentException("endemic-ot: XOR length mismatch");
    byte[] out = new byte[a.length];
    for (int i = 0; i < a.length; i++) out[i] = (byte) (a[i] ^ b[i]);
    return out;
  }

  private static boolean ctEqual(byte[] a, byte[] b) { return MessageDigest.isEqual(a, b); }

  /** {@code sid = H(TAG || rn)}: binds every oracle query to this receiver nonce. */
  public static byte[] sessionId(byte[] rn) { return sha256(TAG_SID, rn); }

  private static byte[] hpk(byte[] sid, int i, byte[] other) { return Lattice.hashToRing(concat(TAG_HPK, sid, u32(i), other)); }

  /** The pad for a slot: SHA-256 in counter mode over {@code TAG || sid || i || slot || ctr || payload}. */
  public static byte[] pad(byte[] sid, int index, int slot, byte[] payload, int len) {
    byte[] out = new byte[len];
    int produced = 0;
    long ctr = 0;
    while (produced < len) {
      byte[] block = sha256(TAG_PAD, sid, u32(index), new byte[] {(byte) (slot & 1)}, u32(ctr), payload);
      for (int k = 0; k < block.length && produced < len; k++) out[produced++] = block[k];
      ctr++;
    }
    return out;
  }

  private static byte[] commit(byte[] sid, int i, int slot, byte[] msg, byte[] pad) {
    return sha256(TAG_COMMIT, sid, u32(i), new byte[] {(byte) (slot & 1)}, msg, pad);
  }

  /** Receiver round: a real key pair per choice, a uniform vector for the other slot, and C = t_real - Hpk(sid, i, N) at the choice slot. */
  public static Receive receive(int[] choices, OtRandom rng) {
    byte[] rn = rng.bytes(SYM_BYTES);
    byte[] sid = sessionId(rn);
    byte[][][] points = new byte[choices.length][][];
    byte[][] rhos = new byte[choices.length][], secretKeys = new byte[choices.length][];
    int[] kept = new int[choices.length];
    for (int i = 0; i < choices.length; i++) {
      int c = choices[i] & 1;
      Lattice.KeyPair kp = Lattice.keygenFips203(rng.bytes(SYM_BYTES));
      byte[] tReal = java.util.Arrays.copyOfRange(kp.publicKey(), 0, TVEC_BYTES);
      byte[] nSlot = Lattice.hashToRing(concat(TAG_N, sid, u32(i), rng.bytes(SYM_BYTES)));
      byte[] cPoint = Lattice.ringSub(tReal, hpk(sid, i, nSlot));
      points[i] = c == 0 ? new byte[][] {cPoint, nSlot} : new byte[][] {nSlot, cPoint};
      rhos[i] = java.util.Arrays.copyOfRange(kp.publicKey(), TVEC_BYTES, PK_BYTES);
      secretKeys[i] = kp.secretKey();
      kept[i] = c;
    }
    return new Receive(new ReceiverMessage(rn, points, rhos), new ReceiverState(kept, secretKeys, rhos, rn, sid));
  }

  private static void validate(ReceiverMessage m) {
    if (m == null || m.rn() == null || m.rn().length != SYM_BYTES) throw new EndemicAbort("endemic LWE OT: malformed session nonce");
    if (m.points() == null || m.rhos() == null || m.points().length != m.rhos().length) throw new EndemicAbort("endemic LWE OT: points/rhos length mismatch");
    for (int i = 0; i < m.points().length; i++) {
      byte[][] pt = m.points()[i];
      if (pt == null || pt.length != 2 || pt[0] == null || pt[1] == null || pt[0].length != TVEC_BYTES || pt[1].length != TVEC_BYTES) {
        throw new EndemicAbort("endemic LWE OT: malformed point pair at index " + i);
      }
      if (m.rhos()[i] == null || m.rhos()[i].length != PK_BYTES - TVEC_BYTES) throw new EndemicAbort("endemic LWE OT: malformed rho at index " + i);
    }
  }

  /** Sender round (random-OT form): encrypt a fresh payload under each slot's effective key and output both pads. {@code tamper} is test-only. */
  public static SenderMessage sendRandom(ReceiverMessage message, OtRandom rng, Consumer<byte[][][]> tamper) {
    validate(message);
    byte[] sid = sessionId(message.rn());
    int n = message.points().length;
    byte[][][] ciphertexts = new byte[n][][], pads = new byte[n][][];
    for (int i = 0; i < n; i++) {
      byte[] p0 = message.points()[i][0], p1 = message.points()[i][1], rho = message.rhos()[i];
      byte[] pk0 = concat(Lattice.ringAdd(p0, hpk(sid, i, p1)), rho);
      byte[] pk1 = concat(Lattice.ringAdd(p1, hpk(sid, i, p0)), rho);
      byte[] r0 = rng.bytes(SYM_BYTES), r1 = rng.bytes(SYM_BYTES);
      byte[] ct0 = Lattice.enc(pk0, r0, rng.bytes(SYM_BYTES));
      byte[] ct1 = Lattice.enc(pk1, r1, rng.bytes(SYM_BYTES));
      ciphertexts[i] = new byte[][] {ct0, ct1};
      pads[i] = new byte[][] {pad(sid, i, 0, r0, ENDEMIC_SECRET_BYTES), pad(sid, i, 1, r1, ENDEMIC_SECRET_BYTES)};
    }
    if (tamper != null) tamper.accept(ciphertexts);
    return new SenderMessage(ciphertexts, pads);
  }

  /** Receiver recovery (random-OT form): decrypt only the chosen ciphertext. */
  public static byte[][] recoverRandom(ReceiverState state, SenderMessage sm) {
    byte[][][] cts = sm == null ? null : sm.ciphertexts();
    if (cts == null || cts.length != state.choices().length) throw new EndemicAbort("endemic LWE OT: ciphertext count does not match the transfer count");
    for (int i = 0; i < cts.length; i++) {
      if (cts[i] == null || cts[i].length != 2 || cts[i][0] == null || cts[i][1] == null || cts[i][0].length != CT_BYTES || cts[i][1].length != CT_BYTES) {
        throw new EndemicAbort("endemic LWE OT: malformed ciphertext pair at index " + i);
      }
    }
    byte[][] out = new byte[cts.length][];
    for (int i = 0; i < cts.length; i++) {
      int c = state.choices()[i] & 1;
      out[i] = pad(state.sid(), i, c, Lattice.dec(state.secretKeys()[i], cts[i][c]), ENDEMIC_SECRET_BYTES);
    }
    return out;
  }

  /** The result of {@link #baseOtRandom}: the sender's pad pairs, the receiver's chosen pads, the session id and the wire messages. */
  public record RandomResult(byte[][][] senderPads, byte[][] recvPads, byte[] sid, ReceiverMessage message, byte[][][] ciphertexts) {}

  /** In-process RANDOM endemic base OT (both parties here, one entropy stream: the receiver round, then the sender round); the random-OT face reused by the combiner. */
  public static RandomResult baseOtRandom(int[] choices, OtRandom rng, Consumer<byte[][][]> tamper) {
    Receive rv = receive(choices, rng);
    SenderMessage sm = sendRandom(rv.message(), rng, tamper);
    byte[][] recvPads = recoverRandom(rv.state(), sm);
    return new RandomResult(sm.senderPads(), recvPads, rv.state().sid(), rv.message(), sm.ciphertexts());
  }

  /** In-process chosen-message endemic base OT. {@code tamperEncrypted} (test-only) corrupts the padded messages on the wire. */
  public static Result baseOT(byte[][][] messages, int[] choices, OtRandom rng, Consumer<byte[][][]> tamperEncrypted) {
    return baseOT(messages, choices, rng, rng, tamperEncrypted);
  }

  /** The same with a separate entropy source per party (the differential test seeds each stream). */
  public static Result baseOT(byte[][][] messages, int[] choices, OtRandom receiverRng, OtRandom rng, Consumer<byte[][][]> tamperEncrypted) {
    if (messages.length != choices.length) throw new IllegalArgumentException("endemicBaseOT: messages/choices length mismatch");
    Receive rv = receive(choices, receiverRng);
    byte[] sid = rv.state().sid();
    int n = messages.length;
    byte[][][] ciphertexts = new byte[n][][], encrypted = new byte[n][][], commitments = new byte[n][][];
    for (int i = 0; i < n; i++) {
      byte[] m0 = messages[i][0], m1 = messages[i][1];
      if (m0.length != m1.length) throw new IllegalArgumentException("endemicBaseOT (index " + i + "): the two messages must be equal length");
      byte[] p0 = rv.message().points()[i][0], p1 = rv.message().points()[i][1], rho = rv.message().rhos()[i];
      byte[] r0 = rng.bytes(SYM_BYTES), r1 = rng.bytes(SYM_BYTES);
      byte[] ct0 = Lattice.enc(concat(Lattice.ringAdd(p0, hpk(sid, i, p1)), rho), r0, rng.bytes(SYM_BYTES));
      byte[] ct1 = Lattice.enc(concat(Lattice.ringAdd(p1, hpk(sid, i, p0)), rho), r1, rng.bytes(SYM_BYTES));
      ciphertexts[i] = new byte[][] {ct0, ct1};
      byte[] pad0 = pad(sid, i, 0, r0, m0.length), pad1 = pad(sid, i, 1, r1, m1.length);
      encrypted[i] = new byte[][] {xor(m0, pad0), xor(m1, pad1)};
      commitments[i] = new byte[][] {commit(sid, i, 0, m0, pad0), commit(sid, i, 1, m1, pad1)};
    }
    if (tamperEncrypted != null) tamperEncrypted.accept(encrypted);
    byte[][] received = new byte[n][];
    for (int i = 0; i < n; i++) {
      int c = choices[i] & 1;
      byte[] payload = Lattice.dec(rv.state().secretKeys()[i], ciphertexts[i][c]);
      byte[] e = encrypted[i][c];
      byte[] pad = pad(sid, i, c, payload, e.length);
      byte[] m = xor(e, pad);
      if (!ctEqual(commit(sid, i, c, m, pad), commitments[i][c])) {
        throw new EndemicAbort("endemic base OT (index " + i + "): sender ciphertext inconsistent with its commitment; aborting");
      }
      received[i] = m;
    }
    return new Result(received, new Transcript(rv.message().rn(), rv.message().points(), rv.message().rhos(), ciphertexts, encrypted, commitments));
  }

  /** The chosen-message endemic base OT as the OT-extension's base-OT seam: {@code new OtChannel(rng, withEndemicBaseOt(), binding)}. */
  public static BaseOtFn withEndemicBaseOt() { return (m, c, r) -> baseOT(m, c, r, null).received(); }
}
