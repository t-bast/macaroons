package tbast

import java.security.SecureRandom

import org.scalatest.funspec.AnyFunSpec
import scodec.bits.{ByteVector, HexStringSyntax}

class MacaroonSpec extends AnyFunSpec {

  describe("macaroons") {

    val secureRandom = new SecureRandom()

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
      assert(m.validate(rootKey, Set.empty))
      assert(!m.validate(rootKey.reverse, Set.empty))
      assert(!m.copy(id = m.id.reverse).validate(rootKey, Set.empty))
    }

    it("should add first party caveats") {
      val rootKey = randomBytes(32)
      val m1 = Macaroon("https://macaroons.io", rootKey, hex"deadbeef")
        .addFirstPartyCaveat(hex"01020304")
        .addFirstPartyCaveat(hex"0102")
      assert(m1.validate(rootKey, Set.empty))
      assert(!m1.validate(rootKey.reverse, Set.empty))
      val m2 = m1.addFirstPartyCaveat(hex"0231")
      assert(m2.validate(rootKey, Set.empty))
      assert(!m2.copy(sig = m1.sig).validate(rootKey, Set.empty))
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
      assert(m.validate(rootKey, discharges))
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

      assert(!m.validate(rootKey, Set.empty))
      assert(!m.validate(rootKey, m.prepareForRequest(Set(discharge1))))
      assert(!m.validate(rootKey, m.prepareForRequest(Set(discharge2))))
      assert(m.validate(rootKey, m.prepareForRequest(Set(discharge1, discharge2))))

      val dischargeInvalidRootKey = Macaroon("Mille sabords", randomBytes(16), hex"0451")
      assert(!m.validate(rootKey, m.prepareForRequest(Set(dischargeInvalidRootKey, discharge2))))

      val dischargeInvalidId = Macaroon("Moule à gaufres", thirdPartyKey2, hex"0451").addFirstPartyCaveat(hex"deadbeef")
      assert(!m.validate(rootKey, m.prepareForRequest(Set(discharge1, dischargeInvalidId))))
    }

    it("should reject discharges not bound to the macaroon") {
      val rootKey = randomBytes(32)
      val thirdPartyKey = randomBytes(32)
      val Some(m) = Macaroon("Malotru", rootKey, hex"0231")
        .addThirdPartyCaveat("Bachi-bouzouk", thirdPartyKey, hex"0451")

      val discharge = Macaroon("Mille sabords", thirdPartyKey, hex"0451")
      assert(m.validate(rootKey, m.prepareForRequest(Set(discharge))))
      assert(!m.validate(rootKey, Set(discharge)))
    }

  }

}
