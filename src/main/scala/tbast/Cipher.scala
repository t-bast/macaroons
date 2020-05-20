package tbast

import javax.crypto.spec.{GCMParameterSpec, SecretKeySpec}
import scodec.bits.ByteVector

import scala.util.Try

object Cipher {

  private val cipherAlgorithm = "AES/GCM/NoPadding"
  private val keyAlgorithm = "AES"
  /** It's ok to use a static all-zeroes nonce because keys are only used once. */
  private val nonce: Array[Byte] = Array.fill(12)(0)
  private val cipherParams = new GCMParameterSpec(96, nonce)

  def encrypt(key: ByteVector, message: ByteVector): Try[ByteVector] = Try {
    val cipher = javax.crypto.Cipher.getInstance(cipherAlgorithm)
    cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, new SecretKeySpec(key.toArray, keyAlgorithm), cipherParams)
    ByteVector(cipher.doFinal(message.toArray))
  }

  def decrypt(key: ByteVector, ciphertext: ByteVector): Try[ByteVector] = Try {
    val cipher = javax.crypto.Cipher.getInstance(cipherAlgorithm)
    cipher.init(javax.crypto.Cipher.DECRYPT_MODE, new SecretKeySpec(key.toArray, keyAlgorithm), cipherParams)
    ByteVector(cipher.doFinal(ciphertext.toArray))
  }

}
