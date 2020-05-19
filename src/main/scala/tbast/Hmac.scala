package tbast

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import scodec.bits.ByteVector

object Hmac {

  /** Compute an HMAC-256 digest. */
  def compute(key: ByteVector, message: ByteVector): ByteVector = {
    val algorithm = "HmacSHA256"
    val hmac256 = Mac.getInstance(algorithm)
    hmac256.init(new SecretKeySpec(key.toArray, algorithm))
    hmac256.update(message.toByteBuffer)
    ByteVector(hmac256.doFinal())
  }

}
