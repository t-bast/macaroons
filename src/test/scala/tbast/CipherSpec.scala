package tbast

import org.scalatest.funspec.AnyFunSpec
import scodec.bits.HexStringSyntax

import scala.util.Success

class CipherSpec extends AnyFunSpec {

  describe("cipher") {

    it("should encrypt and decrypt correctly") {
      val key = hex"01010101010101010101010101010101"
      val message = hex"deadbeef"
      val Success(encrypted) = Cipher.encrypt(key, message)
      val Success(decrypted) = Cipher.decrypt(key, encrypted)
      assert(decrypted === message)
    }

    it("should encrypt deterministically") {
      val key = hex"01010101010101010101010101010101"
      val message = hex"deadbeef"
      val Success(encrypted1) = Cipher.encrypt(key, message)
      val Success(encrypted2) = Cipher.encrypt(key, message)
      assert(encrypted1 === encrypted2)
    }

    it("should fail to encrypt if key is too short") {
      val key = hex"010101010101010101010101010101"
      assert(Cipher.encrypt(key, hex"deadbeef").isFailure)
    }

    it("should fail to encrypt if key is too long") {
      val key = hex"0101010101010101010101010101010101"
      assert(Cipher.encrypt(key, hex"deadbeef").isFailure)
    }

    it("should fail to decrypt tampered message") {
      val key = hex"01010101010101010101010101010101"
      val message = hex"deadbeef"
      val Success(encrypted) = Cipher.encrypt(key, message)
      assert(Cipher.decrypt(key, encrypted.reverse).isFailure)
    }

    it("should fail to decrypt if wrong key is used") {
      val key = hex"000102030405060708090a0b0c0d0e0f"
      val message = hex"deadbeef"
      val Success(encrypted) = Cipher.encrypt(key, message)
      assert(Cipher.decrypt(key.reverse, encrypted).isFailure)
    }

  }

}
