package net.atlasauth.pca.mpc.lwe;

import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.mpc.NetCodec;
import net.atlasauth.pca.mpc.NetWire.NetAbort;
import net.atlasauth.pca.mpc.Ot;
import net.atlasauth.pca.mpc.Ot.OtRandom;
import net.atlasauth.pca.mpc.net.Mesh;
import net.atlasauth.pca.mpc.net.OtNet;

/**
 * The endemic-LWE base OT over the mutual-TLS mesh, wire-compatible with the TypeScript package: the receiver sends 'ot-recv'
 * {rn, points, rhos}, the sender answers 'ot-ct', then the same demo-only 'ot-verify' / 'ot-done' round as the Ed25519 variant.
 * The core party program finds this class by reflection (the adapter depends on the core, never the other way round).
 */
public final class EndemicOtNet {
  private EndemicOtNet() {}

  private static NetAbort abort(Mesh mesh, int peer, String msg) {
    NetAbort ne = new NetAbort("malformed", peer, mesh.selfId, msg);
    mesh.fail(ne, null);
    return ne;
  }

  public static OtNet.Result runOtSender(Mesh mesh, int peer, int count) {
    OtRandom rng = Ot.secureOtRandom();
    Object m = mesh.recv(peer, "ot-recv");
    EndemicOt.ReceiverMessage msg = OtNet.parsing(mesh, peer, "ot-recv", () -> parseReceiver(m, count));
    EndemicOt.SenderMessage sm;
    try {
      sm = EndemicOt.sendRandom(msg, rng, null);
    } catch (RuntimeException e) {
      throw abort(mesh, peer, "lwe sender: " + e.getMessage());
    }
    List<Object> cts = new ArrayList<>();
    for (byte[][] pair : sm.ciphertexts()) cts.add(List.of(NetCodec.b64(pair[0]), NetCodec.b64(pair[1])));
    mesh.send(peer, "ot-ct", cts);
    byte[][][] pads = sm.senderPads();
    // demo-only verification: the receiver reveals choices + pad hashes
    Object v = mesh.recv(peer, "ot-verify");
    boolean ok = OtNet.parsing(mesh, peer, "ot-verify", () -> {
      Map<?, ?> o = v instanceof Map ? (Map<?, ?>) v : null;
      if (o == null || !(o.get("choices") instanceof List) || !(o.get("padHashes") instanceof List)
          || ((List<?>) o.get("choices")).size() != count || ((List<?>) o.get("padHashes")).size() != count) throw new IllegalArgumentException("bad verify message");
      for (int i = 0; i < count; i++) {
        int c = OtNet.bit(((List<?>) o.get("choices")).get(i));
        if (c < 0 || !HexFormat.of().formatHex(OtNet.sha(pads[i][c])).equals(((List<?>) o.get("padHashes")).get(i))) return false;
      }
      return true;
    });
    Map<String, Object> done = new LinkedHashMap<>();
    done.put("matched", ok);
    mesh.send(peer, "ot-done", done);
    mesh.finish();
    byte[][] flat = new byte[count * 2][];
    for (int i = 0; i < count; i++) {
      flat[2 * i] = pads[i][0];
      flat[2 * i + 1] = pads[i][1];
    }
    return new OtNet.Result("lwe", "sender", count, ok, OtNet.digest(flat));
  }

  public static OtNet.Result runOtReceiver(Mesh mesh, int peer, int count) {
    OtRandom rng = Ot.secureOtRandom();
    byte[] cb = rng.bytes(count);
    int[] choices = new int[count];
    for (int i = 0; i < count; i++) choices[i] = cb[i] & 1;
    EndemicOt.Receive rv = EndemicOt.receive(choices, rng);
    Map<String, Object> out = new LinkedHashMap<>();
    out.put("rn", NetCodec.b64(rv.message().rn()));
    List<Object> pts = new ArrayList<>(), rhos = new ArrayList<>();
    for (byte[][] pair : rv.message().points()) pts.add(List.of(NetCodec.b64(pair[0]), NetCodec.b64(pair[1])));
    for (byte[] r : rv.message().rhos()) rhos.add(NetCodec.b64(r));
    out.put("points", pts);
    out.put("rhos", rhos);
    mesh.send(peer, "ot-recv", out);
    Object ctRaw = mesh.recv(peer, "ot-ct");
    byte[][][] cts = OtNet.parsing(mesh, peer, "ot-ct", () -> {
      if (!(ctRaw instanceof List) || ((List<?>) ctRaw).size() != count) throw new IllegalArgumentException("bad ciphertext array");
      byte[][][] r = new byte[count][][];
      for (int i = 0; i < count; i++) r[i] = pair(((List<?>) ctRaw).get(i), "bad ct pair");
      return r;
    });
    byte[][] recvPads = OtNet.parsing(mesh, peer, "ot-ct", () -> EndemicOt.recoverRandom(rv.state(), new EndemicOt.SenderMessage(cts, new byte[0][][])));
    Map<String, Object> vm = new LinkedHashMap<>();
    List<Object> cs = new ArrayList<>(), hs = new ArrayList<>();
    for (int i = 0; i < count; i++) {
      cs.add(choices[i]);
      hs.add(HexFormat.of().formatHex(OtNet.sha(recvPads[i])));
    }
    vm.put("choices", cs);
    vm.put("padHashes", hs);
    mesh.send(peer, "ot-verify", vm);
    Object d = mesh.recv(peer, "ot-done");
    boolean matched = d instanceof Map && Boolean.TRUE.equals(((Map<?, ?>) d).get("matched"));
    mesh.finish();
    return new OtNet.Result("lwe", "receiver", count, matched, OtNet.digest(recvPads));
  }

  private static byte[][] pair(Object o, String err) {
    if (!(o instanceof List) || ((List<?>) o).size() != 2) throw new IllegalArgumentException(err);
    return new byte[][] {NetCodec.unb64(((List<?>) o).get(0), -1), NetCodec.unb64(((List<?>) o).get(1), -1)};
  }

  /** Strict parse of the receiver's 'ot-recv' payload (same shape and canonical-base64 rules as the reference). */
  static EndemicOt.ReceiverMessage parseReceiver(Object m, int count) {
    if (!(m instanceof Map) || !(((Map<?, ?>) m).get("points") instanceof List) || !(((Map<?, ?>) m).get("rhos") instanceof List)
        || ((List<?>) ((Map<?, ?>) m).get("points")).size() != count || ((List<?>) ((Map<?, ?>) m).get("rhos")).size() != count) {
      throw new IllegalArgumentException("bad receiver message");
    }
    Map<?, ?> o = (Map<?, ?>) m;
    byte[][][] points = new byte[count][][];
    byte[][] rhos = new byte[count][];
    for (int i = 0; i < count; i++) {
      points[i] = pair(((List<?>) o.get("points")).get(i), "bad point pair");
      rhos[i] = NetCodec.unb64(((List<?>) o.get("rhos")).get(i), 32);
    }
    return new EndemicOt.ReceiverMessage(NetCodec.unb64(o.get("rn"), 32), points, rhos);
  }
}
