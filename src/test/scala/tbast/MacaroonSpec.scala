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
      assert(m.validate(rootKey))
      assert(!m.validate(rootKey.reverse))
      assert(!m.copy(id = m.id.reverse).validate(rootKey))
    }

    it("should add first party caveats") {
      val rootKey = randomBytes(32)
      val m1 = Macaroon("https://macaroons.io", rootKey, hex"deadbeef")
        .addFirstPartyCaveat(hex"01020304")
        .addFirstPartyCaveat(hex"0102")
      assert(m1.validate(rootKey))
      assert(!m1.validate(rootKey.reverse))
      val m2 = m1.addFirstPartyCaveat(hex"0231")
      assert(m2.validate(rootKey))
      assert(!m2.copy(sig = m1.sig).validate(rootKey))
    }

  }

}
