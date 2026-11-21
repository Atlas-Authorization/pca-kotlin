package net.atlasauth.pca.mpc.lwe;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.mpc.NetCodec;
import net.atlasauth.pca.mpc.Ot;
import org.junit.jupiter.api.Test;

/** Wire-shape checks of the network OT messages (no sockets): the receiver's 'ot-recv' payload must survive the strict parser and drive the sender. */
class EndemicOtNetTest {
  private static Map<String, Object> wire(EndemicOt.ReceiverMessage m) {
    Map<String, Object> o = new LinkedHashMap<>();
    o.put("rn", NetCodec.b64(m.rn()));
    List<Object> pts = new ArrayList<>(), rhos = new ArrayList<>();
    for (byte[][] p : m.points()) pts.add(List.of(NetCodec.b64(p[0]), NetCodec.b64(p[1])));
    for (byte[] r : m.rhos()) rhos.add(NetCodec.b64(r));
    o.put("points", pts);
    o.put("rhos", rhos);
    return o;
  }

  @Test
  void receiverMessageRoundTripsAndPadsAgree() {
    assumeTrue(Lattice.available(), "liblweot not available");
    int[] choices = {0, 1, 1, 0};
    Ot.OtRandom rng = Ot.secureOtRandom();
    EndemicOt.Receive rv = EndemicOt.receive(choices, rng);
    EndemicOt.ReceiverMessage parsed = EndemicOtNet.parseReceiver(wire(rv.message()), choices.length);
    EndemicOt.SenderMessage sm = EndemicOt.sendRandom(parsed, rng, null);
    byte[][] got = EndemicOt.recoverRandom(rv.state(), sm);
    for (int i = 0; i < choices.length; i++) assertArrayEquals(sm.senderPads()[i][choices[i]], got[i]);
  }

  @Test
  void parserRefusesMalformedMessages() {
    Map<String, Object> ok = new LinkedHashMap<>();
    String z32 = NetCodec.b64(new byte[32]);
    ok.put("rn", z32);
    ok.put("points", List.of(List.of(z32, z32)));
    ok.put("rhos", List.of(z32));
    EndemicOtNet.parseReceiver(ok, 1);
    assertThrows(IllegalArgumentException.class, () -> EndemicOtNet.parseReceiver(ok, 2));
    assertThrows(IllegalArgumentException.class, () -> EndemicOtNet.parseReceiver("x", 1));
    Map<String, Object> badRn = new LinkedHashMap<>(ok);
    badRn.put("rn", NetCodec.b64(new byte[31]));
    assertThrows(IllegalArgumentException.class, () -> EndemicOtNet.parseReceiver(badRn, 1));
    Map<String, Object> badRho = new LinkedHashMap<>(ok);
    badRho.put("rhos", List.of(NetCodec.b64(new byte[31])));
    assertThrows(IllegalArgumentException.class, () -> EndemicOtNet.parseReceiver(badRho, 1));
    Map<String, Object> alias = new LinkedHashMap<>(ok);
    alias.put("rn", z32.substring(0, z32.length() - 2) + "B=");
    assertThrows(IllegalArgumentException.class, () -> EndemicOtNet.parseReceiver(alias, 1));
    Map<String, Object> badPair = new LinkedHashMap<>(ok);
    badPair.put("points", List.of(List.of(z32)));
    assertThrows(IllegalArgumentException.class, () -> EndemicOtNet.parseReceiver(badPair, 1));
  }
}
