package net.atlasauth.pca.fhe.seal;

import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.NativeLong;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.ByteByReference;
import com.sun.jna.ptr.IntByReference;
import com.sun.jna.ptr.LongByReference;
import com.sun.jna.ptr.PointerByReference;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayDeque;
import java.util.Base64;
import java.util.Deque;
import java.util.regex.Pattern;

/**
 * Homomorphic evaluation of PCA's risk gate (BFV on Microsoft SEAL), the same circuit as the TypeScript reference: encrypted inputs times public
 * weights, summed across slots with Galois rotations, the budget folded in with a plaintext negate and add. BFV is never reimplemented: every
 * lattice operation is SEAL's own C export API (native/src/seal/c, the one SEAL.NET binds) through JNA. SEAL objects cross the API as the base64
 * of their SEAL native stream, byte-compatible with node-seal. Point {@code -Dpca.sealc.lib} at libsealc built from the pinned SEAL tag.
 */
public final class FheSeal {
  private FheSeal() {}

  public static final int POLY_MODULUS_DEGREE = 8192;
  public static final int PLAIN_MODULUS_BITS = 30;
  public static final long PLAIN_MODULUS = 1_073_692_673L;
  public static final long SIGNED_BOUND = PLAIN_MODULUS / 2;
  public static final int RISK_DIM = 6;
  private static final int MIN_NOISE_BUDGET_BITS = 16;
  private static final byte BFV = 1, COMPR_NONE = 0, COMPR_ZSTD = 2;
  private static final int TC128 = 128;
  private static final Pattern B64 = Pattern.compile("^[A-Za-z0-9+/]*={0,2}$");

  /** The public gate policy: fixed-point weights, kappa-weighted weights and the budget bound (scale S, budget at S^2). */
  public record Policy(long scale, long dim, long[] weightsScaled, long[] kappaWeightsScaled, long budgetScaled, double kappa) {}

  public record Keyset(String secretKey, String publicKey, String relinKeys, String galoisKeys) {}

  public record EncryptedGate(String encRiskRaw, String encSlack) {}

  /** rScaled is r at scale S^2 clamped to [0,S^2]; admit is slack &gt;= 0. */
  public record Verdict(long rScaled, long slack, boolean admit) {}

  /** The slice of SEAL's C export API the gate uses (prototypes follow SEAL 4.1.x; HRESULT is C long). */
  interface Sealc extends Library {
    NativeLong EncParams_Create1(byte scheme, PointerByReference p);
    NativeLong EncParams_Destroy(Pointer p);
    NativeLong EncParams_SetPolyModulusDegree(Pointer p, long degree);
    NativeLong EncParams_SetCoeffModulus(Pointer p, long length, Pointer[] coeffs);
    NativeLong EncParams_SetPlainModulus1(Pointer p, Pointer modulus);
    NativeLong CoeffModulus_BFVDefault(long degree, int secLevel, LongByReference length, Pointer[] coeffs);
    NativeLong CoeffModulus_Create1(long degree, long length, int[] bitSizes, Pointer[] coeffs);
    NativeLong Modulus_Destroy(Pointer p);
    NativeLong Modulus_Value(Pointer p, LongByReference value);
    NativeLong SEALContext_Create(Pointer parms, byte expandModChain, int secLevel, PointerByReference ctx);
    NativeLong SEALContext_Destroy(Pointer p);
    NativeLong SEALContext_ParametersSet(Pointer p, ByteByReference ok);
    NativeLong BatchEncoder_Create(Pointer ctx, PointerByReference enc);
    NativeLong BatchEncoder_Destroy(Pointer p);
    NativeLong BatchEncoder_Encode2(Pointer p, long count, long[] values, Pointer destination);
    NativeLong BatchEncoder_Decode2(Pointer p, Pointer plain, LongByReference count, long[] destination, Pointer pool);
    NativeLong BatchEncoder_GetSlotCount(Pointer p, LongByReference slots);
    NativeLong KeyGenerator_Create1(Pointer ctx, PointerByReference gen);
    NativeLong KeyGenerator_Destroy(Pointer p);
    NativeLong KeyGenerator_SecretKey(Pointer gen, PointerByReference sk);
    NativeLong KeyGenerator_CreatePublicKey(Pointer gen, byte saveSeed, PointerByReference pk);
    NativeLong KeyGenerator_CreateRelinKeys(Pointer gen, byte saveSeed, PointerByReference rk);
    NativeLong KeyGenerator_CreateGaloisKeysAll(Pointer gen, byte saveSeed, PointerByReference gk);
    NativeLong PublicKey_Create1(PointerByReference p);
    NativeLong PublicKey_Destroy(Pointer p);
    NativeLong PublicKey_SaveSize(Pointer p, byte compr, LongByReference size);
    NativeLong PublicKey_Save(Pointer p, byte[] out, long size, byte compr, LongByReference written);
    NativeLong PublicKey_Load(Pointer p, Pointer ctx, byte[] in, long size, LongByReference read);
    NativeLong SecretKey_Create1(PointerByReference p);
    NativeLong SecretKey_Destroy(Pointer p);
    NativeLong SecretKey_SaveSize(Pointer p, byte compr, LongByReference size);
    NativeLong SecretKey_Save(Pointer p, byte[] out, long size, byte compr, LongByReference written);
    NativeLong SecretKey_Load(Pointer p, Pointer ctx, byte[] in, long size, LongByReference read);
    NativeLong KSwitchKeys_Create1(PointerByReference p);
    NativeLong KSwitchKeys_Destroy(Pointer p);
    NativeLong KSwitchKeys_SaveSize(Pointer p, byte compr, LongByReference size);
    NativeLong KSwitchKeys_Save(Pointer p, byte[] out, long size, byte compr, LongByReference written);
    NativeLong KSwitchKeys_Load(Pointer p, Pointer ctx, byte[] in, long size, LongByReference read);
    NativeLong Ciphertext_Create1(Pointer pool, PointerByReference p);
    NativeLong Ciphertext_Create2(Pointer copy, PointerByReference p);
    NativeLong Ciphertext_Destroy(Pointer p);
    NativeLong Ciphertext_SaveSize(Pointer p, byte compr, LongByReference size);
    NativeLong Ciphertext_Save(Pointer p, byte[] out, long size, byte compr, LongByReference written);
    NativeLong Ciphertext_Load(Pointer p, Pointer ctx, byte[] in, long size, LongByReference read);
    NativeLong Plaintext_Create1(Pointer pool, PointerByReference p);
    NativeLong Plaintext_Destroy(Pointer p);
    NativeLong Encryptor_Create(Pointer ctx, Pointer pk, Pointer sk, PointerByReference p);
    NativeLong Encryptor_Encrypt(Pointer p, Pointer plain, Pointer destination, Pointer pool);
    NativeLong Encryptor_Destroy(Pointer p);
    NativeLong Decryptor_Create(Pointer ctx, Pointer sk, PointerByReference p);
    NativeLong Decryptor_Destroy(Pointer p);
    NativeLong Decryptor_Decrypt(Pointer p, Pointer encrypted, Pointer destination);
    NativeLong Decryptor_InvariantNoiseBudget(Pointer p, Pointer encrypted, IntByReference budget);
    NativeLong Evaluator_Create(Pointer ctx, PointerByReference p);
    NativeLong Evaluator_Destroy(Pointer p);
    NativeLong Evaluator_Negate(Pointer p, Pointer encrypted, Pointer destination);
    NativeLong Evaluator_Add(Pointer p, Pointer a, Pointer b, Pointer destination);
    NativeLong Evaluator_AddPlain(Pointer p, Pointer encrypted, Pointer plain, Pointer destination);
    NativeLong Evaluator_MultiplyPlain(Pointer p, Pointer encrypted, Pointer plain, Pointer destination, Pointer pool);
    NativeLong Evaluator_RotateRows(Pointer p, Pointer encrypted, int steps, Pointer galoisKeys, Pointer destination, Pointer pool);
    NativeLong Evaluator_RotateColumns(Pointer p, Pointer encrypted, Pointer galoisKeys, Pointer destination, Pointer pool);
  }

  private static String packaged(String name, String override) {
    String p = net.atlasauth.pca.NativeLibs.resolve(FheSeal.class, name, override);
    return p != null ? p : name; // else the system library path
  }

  private static volatile Sealc lib;

  static Sealc lib() {
    Sealc l = lib;
    if (l == null) {
      synchronized (FheSeal.class) {
        if (lib == null) lib = Native.load(packaged("sealc", System.getProperty("pca.sealc.lib")), Sealc.class);
        l = lib;
      }
    }
    return l;
  }

  /** True when libsealc can be loaded (tests skip, or fail when required, on false). */
  public static boolean available() {
    try {
      lib();
      return true;
    } catch (UnsatisfiedLinkError | RuntimeException e) {
      return false;
    }
  }

  private static void chk(String op, NativeLong hr) {
    if (hr.longValue() < 0) throw new IllegalStateException("seal " + op + " failed: 0x" + Integer.toHexString((int) hr.longValue())); // negative is failure; S_FALSE (1) is success
  }

  /** Releases native handles in reverse order on every exit path. */
  private static final class Scope implements AutoCloseable {
    private final Deque<Runnable> fns = new ArrayDeque<>();

    Pointer adopt(Pointer h, java.util.function.Consumer<Pointer> destroy) {
      fns.push(() -> destroy.accept(h));
      return h;
    }

    @Override public void close() {
      while (!fns.isEmpty()) fns.pop().run();
    }
  }

  private static final class Ctx {
    Pointer context, encoder;
    int slots;
  }

  /** Reject anything that is not a well-formed SEAL stream envelope (magic, header size, compression mode, declared size == length). */
  public static byte[] assertSealBlob(String blob, String what) {
    if (blob == null || blob.length() < 24 || blob.length() % 4 != 0 || !B64.matcher(blob).matches())
      throw new IllegalArgumentException(what + ": not a serialized SEAL object (bad encoding)");
    byte[] b = Base64.getDecoder().decode(blob);
    if (b.length < 16 || b[0] != 0x5e || (b[1] & 0xff) != 0xa1 || b[2] != 16 || (b[5] & 0xff) > 2 || b[6] != 0 || b[7] != 0)
      throw new IllegalArgumentException(what + ": not a serialized SEAL object (bad header)");
    long size = ByteBuffer.wrap(b, 8, 8).order(ByteOrder.LITTLE_ENDIAN).getLong();
    if (size != b.length)
      throw new IllegalArgumentException(what + ": truncated or padded SEAL object (declared " + Long.toUnsignedString(size) + " bytes, got " + b.length + ")");
    return b;
  }

  /** The policy crosses a trust boundary: validate every coefficient exactly as the policy builder would have produced it. */
  public static void requirePolicy(Policy p) {
    if (p == null) throw new IllegalArgumentException("policy must be an object");
    if (p.scale() <= 0) throw new IllegalArgumentException("policy.scale must be a positive integer");
    if (p.weightsScaled() == null || p.kappaWeightsScaled() == null) throw new IllegalArgumentException("policy weight vectors are required");
    if (outOfRange(p.budgetScaled())) throw new IllegalArgumentException("policy coefficients must be integers with |value| < SIGNED_BOUND");
    for (long[] vs : new long[][] {p.weightsScaled(), p.kappaWeightsScaled()})
      for (long v : vs)
        if (outOfRange(v)) throw new IllegalArgumentException("policy coefficients must be integers with |value| < SIGNED_BOUND");
    if (p.dim() != RISK_DIM) throw new IllegalArgumentException("policy.dim must be " + RISK_DIM);
    if (p.weightsScaled().length != RISK_DIM || p.kappaWeightsScaled().length != RISK_DIM)
      throw new IllegalArgumentException("policy weight vectors must have length " + RISK_DIM);
  }

  private static boolean outOfRange(long v) {
    return v <= -SIGNED_BOUND || v >= SIGNED_BOUND;
  }

  private static Pointer made(PointerByReference r) {
    return r.getValue();
  }

  private static Ctx newCtx(Scope s) {
    Sealc l = lib();
    PointerByReference r = new PointerByReference();
    chk("EncParams_Create", l.EncParams_Create1(BFV, r));
    Pointer parms = s.adopt(made(r), l::EncParams_Destroy);
    chk("SetPolyModulusDegree", l.EncParams_SetPolyModulusDegree(parms, POLY_MODULUS_DEGREE));
    LongByReference n = new LongByReference();
    chk("BFVDefault(length)", l.CoeffModulus_BFVDefault(POLY_MODULUS_DEGREE, TC128, n, null));
    Pointer[] coeffs = new Pointer[(int) n.getValue()];
    chk("BFVDefault", l.CoeffModulus_BFVDefault(POLY_MODULUS_DEGREE, TC128, n, coeffs));
    for (Pointer m : coeffs) s.adopt(m, l::Modulus_Destroy);
    chk("SetCoeffModulus", l.EncParams_SetCoeffModulus(parms, coeffs.length, coeffs));
    Pointer[] plain = new Pointer[1];
    chk("PlainModulus.Batching", l.CoeffModulus_Create1(POLY_MODULUS_DEGREE, 1, new int[] {PLAIN_MODULUS_BITS}, plain));
    s.adopt(plain[0], l::Modulus_Destroy);
    LongByReference live = new LongByReference();
    chk("Modulus_Value", l.Modulus_Value(plain[0], live));
    if (live.getValue() != PLAIN_MODULUS) throw new IllegalStateException("plain modulus drift: live " + live.getValue() + " != documented " + PLAIN_MODULUS);
    chk("SetPlainModulus", l.EncParams_SetPlainModulus1(parms, plain[0]));
    Ctx c = new Ctx();
    r = new PointerByReference();
    chk("SEALContext_Create", l.SEALContext_Create(parms, (byte) 1, TC128, r));
    c.context = s.adopt(made(r), l::SEALContext_Destroy);
    ByteByReference ok = new ByteByReference();
    chk("ParametersSet", l.SEALContext_ParametersSet(c.context, ok));
    if (ok.getValue() == 0) throw new IllegalStateException("SEAL rejected the BFV parameters");
    r = new PointerByReference();
    chk("BatchEncoder_Create", l.BatchEncoder_Create(c.context, r));
    c.encoder = s.adopt(made(r), l::BatchEncoder_Destroy);
    LongByReference sc = new LongByReference();
    chk("SlotCount", l.BatchEncoder_GetSlotCount(c.encoder, sc));
    c.slots = (int) sc.getValue();
    return c;
  }

  private enum Kind { PUBLIC, SECRET, KEYS, CIPHER }

  private static Pointer create(Scope s, Kind k) {
    Sealc l = lib();
    PointerByReference r = new PointerByReference();
    switch (k) {
      case PUBLIC -> { chk("create", l.PublicKey_Create1(r)); return s.adopt(made(r), l::PublicKey_Destroy); }
      case SECRET -> { chk("create", l.SecretKey_Create1(r)); return s.adopt(made(r), l::SecretKey_Destroy); }
      case KEYS -> { chk("create", l.KSwitchKeys_Create1(r)); return s.adopt(made(r), l::KSwitchKeys_Destroy); }
      default -> { chk("create", l.Ciphertext_Create1(null, r)); return s.adopt(made(r), l::Ciphertext_Destroy); }
    }
  }

  private static Pointer load(Ctx c, Scope s, Kind k, String blob, String what) {
    byte[] raw = assertSealBlob(blob, what);
    Pointer p = create(s, k);
    Sealc l = lib();
    LongByReference used = new LongByReference();
    NativeLong hr = switch (k) {
      case PUBLIC -> l.PublicKey_Load(p, c.context, raw, raw.length, used);
      case SECRET -> l.SecretKey_Load(p, c.context, raw, raw.length, used);
      case KEYS -> l.KSwitchKeys_Load(p, c.context, raw, raw.length, used);
      default -> l.Ciphertext_Load(p, c.context, raw, raw.length, used);
    };
    chk("load " + what, hr);
    return p;
  }

  private static String save(Kind k, Pointer p, byte compr) {
    Sealc l = lib();
    LongByReference size = new LongByReference();
    chk("save size", switch (k) {
      case PUBLIC -> l.PublicKey_SaveSize(p, compr, size);
      case SECRET -> l.SecretKey_SaveSize(p, compr, size);
      case KEYS -> l.KSwitchKeys_SaveSize(p, compr, size);
      default -> l.Ciphertext_SaveSize(p, compr, size);
    });
    byte[] buf = new byte[(int) size.getValue()];
    LongByReference n = new LongByReference();
    chk("save", switch (k) {
      case PUBLIC -> l.PublicKey_Save(p, buf, buf.length, compr, n);
      case SECRET -> l.SecretKey_Save(p, buf, buf.length, compr, n);
      case KEYS -> l.KSwitchKeys_Save(p, buf, buf.length, compr, n);
      default -> l.Ciphertext_Save(p, buf, buf.length, compr, n);
    });
    return Base64.getEncoder().encodeToString(java.util.Arrays.copyOf(buf, (int) n.getValue()));
  }

  private static Pointer plain(Scope s) {
    PointerByReference r = new PointerByReference();
    chk("Plaintext_Create", lib().Plaintext_Create1(null, r));
    return s.adopt(made(r), lib()::Plaintext_Destroy);
  }

  private static Pointer encode(Ctx c, Scope s, long... values) {
    long[] slots = new long[c.slots];
    System.arraycopy(values, 0, slots, 0, values.length);
    Pointer pt = plain(s);
    chk("Encode", lib().BatchEncoder_Encode2(c.encoder, slots.length, slots, pt));
    return pt;
  }

  /** Generate the key material (the secret key stays with the policy owner). */
  public static Keyset keygen() {
    Sealc l = lib();
    try (Scope s = new Scope()) {
      Ctx c = newCtx(s);
      PointerByReference r = new PointerByReference();
      chk("KeyGenerator_Create", l.KeyGenerator_Create1(c.context, r));
      Pointer gen = s.adopt(made(r), l::KeyGenerator_Destroy);
      r = new PointerByReference();
      chk("SecretKey", l.KeyGenerator_SecretKey(gen, r));
      Pointer sk = made(r); // a view owned by the generator: destroying it would double free
      r = new PointerByReference();
      chk("CreatePublicKey", l.KeyGenerator_CreatePublicKey(gen, (byte) 0, r));
      Pointer pk = s.adopt(made(r), l::PublicKey_Destroy);
      r = new PointerByReference();
      chk("CreateRelinKeys", l.KeyGenerator_CreateRelinKeys(gen, (byte) 0, r));
      Pointer rk = s.adopt(made(r), l::KSwitchKeys_Destroy);
      r = new PointerByReference();
      chk("CreateGaloisKeys", l.KeyGenerator_CreateGaloisKeysAll(gen, (byte) 0, r));
      Pointer gk = s.adopt(made(r), l::KSwitchKeys_Destroy);
      return new Keyset(save(Kind.SECRET, sk, COMPR_ZSTD), save(Kind.PUBLIC, pk, COMPR_ZSTD), save(Kind.KEYS, rk, COMPR_ZSTD), save(Kind.KEYS, gk, COMPR_ZSTD));
    }
  }

  /** BFV-encrypt the quantized risk-input vector (length 6, each a non-negative integer below the signed bound). */
  public static String encryptRiskInputs(String publicKey, long[] inputsScaled) {
    if (inputsScaled == null || inputsScaled.length != RISK_DIM) throw new IllegalArgumentException("inputsScaled must have length " + RISK_DIM);
    for (long v : inputsScaled)
      if (v < 0 || v >= SIGNED_BOUND) throw new IllegalArgumentException("each scaled input must be a non-negative integer below the signed bound");
    Sealc l = lib();
    try (Scope s = new Scope()) {
      Ctx c = newCtx(s);
      Pointer pk = load(c, s, Kind.PUBLIC, publicKey, "publicKey");
      PointerByReference r = new PointerByReference();
      chk("Encryptor_Create", l.Encryptor_Create(c.context, pk, null, r));
      Pointer enc = s.adopt(made(r), l::Encryptor_Destroy);
      Pointer pt = encode(c, s, inputsScaled), ct = create(s, Kind.CIPHER);
      chk("Encrypt", l.Encryptor_Encrypt(enc, pt, ct, null));
      return save(Kind.CIPHER, ct, COMPR_ZSTD);
    }
  }

  /**
   * Evaluate the gate blind with the reference's operation order: multiplyPlain, sumElements (rotateColumns+add, then rotateRows/rotateColumns/add
   * for steps N/4..1), negate, addPlain. Never constructs a decryptor.
   */
  public static EncryptedGate evalRiskGate(String publicKey, String galoisKeys, String encInputs, Policy policy) {
    requirePolicy(policy);
    Sealc l = lib();
    try (Scope s = new Scope()) {
      Ctx c = newCtx(s);
      Pointer gk = load(c, s, Kind.KEYS, galoisKeys, "galoisKeys");
      Pointer pk = load(c, s, Kind.PUBLIC, publicKey, "publicKey");
      PointerByReference r = new PointerByReference();
      chk("Evaluator_Create", l.Evaluator_Create(c.context, r));
      Pointer ev = s.adopt(made(r), l::Evaluator_Destroy);
      r = new PointerByReference();
      chk("Encryptor_Create", l.Encryptor_Create(c.context, pk, null, r));
      Pointer enc = s.adopt(made(r), l::Encryptor_Destroy);
      Pointer x = load(c, s, Kind.CIPHER, encInputs, "encInputs");

      Pointer riskRaw = dot(l, c, s, ev, enc, gk, x, policy.weightsScaled());
      Pointer kappaRisk = dot(l, c, s, ev, enc, gk, x, policy.kappaWeightsScaled());
      Pointer neg = create(s, Kind.CIPHER), slack = create(s, Kind.CIPHER);
      chk("Negate", l.Evaluator_Negate(ev, kappaRisk, neg));
      chk("AddPlain", l.Evaluator_AddPlain(ev, neg, encode(c, s, policy.budgetScaled()), slack));
      return new EncryptedGate(save(Kind.CIPHER, riskRaw, COMPR_ZSTD), save(Kind.CIPHER, slack, COMPR_ZSTD));
    }
  }

  private static Pointer dot(Sealc l, Ctx c, Scope s, Pointer ev, Pointer enc, Pointer gk, Pointer x, long[] coeffs) {
    boolean zero = true;
    for (long v : coeffs) zero &= v == 0;
    // SEAL refuses multiplyPlain by an all-zero plaintext (transparent result): the dot product is then a fresh encryption of zero.
    if (zero) {
      Pointer ct = create(s, Kind.CIPHER);
      chk("Encrypt", l.Encryptor_Encrypt(enc, encode(c, s), ct, null));
      return ct;
    }
    Pointer prod = create(s, Kind.CIPHER);
    chk("MultiplyPlain", l.Evaluator_MultiplyPlain(ev, x, encode(c, s, coeffs), prod, null));
    PointerByReference r = new PointerByReference();
    chk("Ciphertext_Create2", l.Ciphertext_Create2(prod, r));
    Pointer temp = s.adopt(made(r), l::Ciphertext_Destroy), dest = create(s, Kind.CIPHER);
    chk("RotateColumns", l.Evaluator_RotateColumns(ev, temp, gk, dest, null));
    chk("Add", l.Evaluator_Add(ev, temp, dest, temp));
    for (int steps = POLY_MODULUS_DEGREE / 4; steps >= 1; steps /= 2) {
      chk("RotateRows", l.Evaluator_RotateRows(ev, temp, steps, gk, dest, null));
      chk("RotateColumns", l.Evaluator_RotateColumns(ev, dest, gk, dest, null));
      chk("Add", l.Evaluator_Add(ev, temp, dest, temp));
    }
    return temp;
  }

  /** Decrypt the gate outputs and read the verdict; fails closed when the noise budget is exhausted (wrong key, corrupt or foreign ciphertext). */
  public static Verdict decryptVerdict(String secretKey, String encRiskRaw, String encSlack, Policy policy) {
    requirePolicy(policy);
    Sealc l = lib();
    try (Scope s = new Scope()) {
      Ctx c = newCtx(s);
      Pointer sk = load(c, s, Kind.SECRET, secretKey, "secretKey");
      PointerByReference r = new PointerByReference();
      chk("Decryptor_Create", l.Decryptor_Create(c.context, sk, r));
      Pointer dec = s.adopt(made(r), l::Decryptor_Destroy);
      Pointer[] cts = {load(c, s, Kind.CIPHER, encRiskRaw, "encRiskRaw"), load(c, s, Kind.CIPHER, encSlack, "encSlack")};
      for (Pointer ct : cts) {
        IntByReference nb = new IntByReference();
        chk("InvariantNoiseBudget", l.Decryptor_InvariantNoiseBudget(dec, ct, nb));
        if (nb.getValue() < MIN_NOISE_BUDGET_BITS)
          throw new IllegalStateException("decryptVerdict: ciphertext has no noise budget left (wrong key, corrupted, or not produced by the gate)");
      }
      long[] v = new long[2];
      for (int i = 0; i < 2; i++) {
        Pointer pt = plain(s);
        chk("Decrypt", l.Decryptor_Decrypt(dec, cts[i], pt));
        long[] out = new long[c.slots];
        LongByReference n = new LongByReference(c.slots); // SEAL does not accept a null destination
        chk("Decode", l.BatchEncoder_Decode2(c.encoder, pt, n, out, null));
        v[i] = out[0];
      }
      long cap = Math.multiplyExact(policy.scale(), policy.scale());
      return new Verdict(Math.min(Math.max(v[0], 0), cap), v[1], v[1] >= 0);
    }
  }

  /** Re-save a base64 SEAL ciphertext uncompressed, for byte comparison independent of the zstd build. */
  public static String canonicalCipher(String blob) {
    try (Scope s = new Scope()) {
      Ctx c = newCtx(s);
      return save(Kind.CIPHER, load(c, s, Kind.CIPHER, blob, "ciphertext"), COMPR_NONE);
    }
  }
}
