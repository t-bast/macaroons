package tbast

import java.nio.charset.StandardCharsets

import org.scalatest.funspec.AnyFunSpec
import scodec.bits.{ByteVector, HexStringSyntax}

class HmacSpec extends AnyFunSpec {

  describe("hmac") {

    it("should match wikipedia example") {
      val key = ByteVector("key".getBytes(StandardCharsets.US_ASCII))
      val message = ByteVector("The quick brown fox jumps over the lazy dog".getBytes(StandardCharsets.US_ASCII))
      val expected = hex"f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"
      assert(Hmac.compute(key, message) === expected)
    }

  }

}
