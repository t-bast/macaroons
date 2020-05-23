package tbast

import java.security.SecureRandom

import org.scalatest.funspec.AnyFunSpec
import scodec.bits.{ByteVector, HexStringSyntax}

class MacaroonSpec extends AnyFunSpec {

  describe("macaroons") {

    val secureRandom = new SecureRandom()
    val acceptAll = (_: ByteVector) => true
    val rejectAll = (_: ByteVector) => false

    def randomBytes(length: Int): ByteVector = {
      val buffer = new Array[Byte](length)
      secureRandom.nextBytes(buffer)
      ByteVector.view(buffer)
    }

    it("should create valid empty macaroon") {
      val rootKey = randomBytes(32)
      val m = Macaroon("https://macaroons.io", rootKey, hex"deadbeef")
      assert(m.location === "https://macaroons.io")
      assert(m.caveats.isEmpty)
      assert(m.validate(rootKey, Set.empty, acceptAll))
      assert(m.validate(rootKey, Set.empty, rejectAll))
      assert(!m.validate(rootKey.reverse, Set.empty, acceptAll))
      assert(!m.copy(id = m.id.reverse).validate(rootKey, Set.empty, acceptAll))
    }

    it("should add first party caveats") {
      val rootKey = randomBytes(32)
      val m1 = Macaroon("https://macaroons.io", rootKey, hex"deadbeef")
        .addFirstPartyCaveat(hex"01020304")
        .addFirstPartyCaveat(hex"0102")
      assert(m1.validate(rootKey, Set.empty, acceptAll))
      assert(!m1.validate(rootKey.reverse, Set.empty, acceptAll))
      val m2 = m1.addFirstPartyCaveat(hex"0231")
      assert(m2.validate(rootKey, Set.empty, acceptAll))
      assert(!m2.copy(sig = m1.sig).validate(rootKey, Set.empty, acceptAll))
    }

    it("should reject first party caveats that the application considers invalid") {
      val rootKey = randomBytes(32)
      val m = Macaroon("https://macaroons.io", rootKey, hex"deadbeef")
        .addFirstPartyCaveat(hex"01020304")
        .addFirstPartyCaveat(hex"0102")
      assert(m.validate(rootKey, Set.empty, acceptAll))
      assert(!m.validate(rootKey, Set.empty, rejectAll))
      assert(!m.validate(rootKey, Set.empty, p => p == hex"01020304"))
      assert(!m.validate(rootKey, Set.empty, p => p == hex"0102"))
    }

    it("should add third party caveats") {
      val rootKey = randomBytes(32)
      val thirdPartyKey1 = randomBytes(32)
      val thirdPartyKey2 = randomBytes(16)
      val Some(m) = Macaroon("Malotru", rootKey, hex"0231")
        .addThirdPartyCaveat("Mille sabords", thirdPartyKey1, hex"0451")
        .flatMap(_.addThirdPartyCaveat("Moule à gaufres", thirdPartyKey2, hex"06c1"))

      val discharges = m.prepareForRequest(Set(
        Macaroon("Mille sabords", thirdPartyKey1, hex"0451"),
        Macaroon("Moule à gaufres", thirdPartyKey2, hex"06c1").addFirstPartyCaveat(hex"deadbeef")
      ))

      assert(m.caveats.length === 2)
      assert(m.validate(rootKey, discharges, acceptAll))
    }

    it("should reject invalid discharge") {
      val rootKey = randomBytes(32)
      val thirdPartyKey1 = randomBytes(32)
      val thirdPartyKey2 = randomBytes(16)
      val Some(m) = Macaroon("Malotru", rootKey, hex"0231")
        .addThirdPartyCaveat("Bachi-bouzouk", thirdPartyKey1, hex"0451")
        .flatMap(_.addThirdPartyCaveat("Ectoplasme", thirdPartyKey2, hex"06c1"))

      val discharge1 = Macaroon("Mille sabords", thirdPartyKey1, hex"0451")
      val discharge2 = Macaroon("Moule à gaufres", thirdPartyKey2, hex"06c1").addFirstPartyCaveat(hex"deadbeef")

      assert(!m.validate(rootKey, Set.empty, acceptAll))
      assert(!m.validate(rootKey, m.prepareForRequest(Set(discharge1)), acceptAll))
      assert(!m.validate(rootKey, m.prepareForRequest(Set(discharge2)), acceptAll))
      assert(m.validate(rootKey, m.prepareForRequest(Set(discharge1, discharge2)), acceptAll))

      val dischargeInvalidRootKey = Macaroon("Mille sabords", randomBytes(16), hex"0451")
      assert(!m.validate(rootKey, m.prepareForRequest(Set(dischargeInvalidRootKey, discharge2)), acceptAll))

      val dischargeInvalidId = Macaroon("Moule à gaufres", thirdPartyKey2, hex"0451").addFirstPartyCaveat(hex"deadbeef")
      assert(!m.validate(rootKey, m.prepareForRequest(Set(discharge1, dischargeInvalidId)), acceptAll))
    }

    it("should reject discharges not bound to the macaroon") {
      val rootKey = randomBytes(32)
      val thirdPartyKey = randomBytes(32)
      val Some(m) = Macaroon("Malotru", rootKey, hex"0231")
        .addThirdPartyCaveat("Bachi-bouzouk", thirdPartyKey, hex"0451")

      val discharge = Macaroon("Mille sabords", thirdPartyKey, hex"0451")
      assert(m.validate(rootKey, m.prepareForRequest(Set(discharge)), acceptAll))
      assert(!m.validate(rootKey, Set(discharge), acceptAll))
    }

  }

}
