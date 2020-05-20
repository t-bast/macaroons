package tbast

import scodec.bits.ByteVector

import scala.collection.immutable.Queue

/**
 * Macaroons are authorization credentials that provide flexible support for controlled sharing in decentralized,
 * distributed systems.
 * Macaroons are a form of bearer credentials (much like commonly-used cookies on the web).
 *
 * @param location hint to the target’s location.
 * @param id       macaroon identifier.
 * @param caveats  macaroon's caveats (similar to capabilities).
 * @param sig      chained-MAC signature of the macaroon's contents.
 */
case class Macaroon(location: String, id: ByteVector, caveats: Queue[Caveat], sig: ByteVector) {

  private def addCaveat(caveat: Caveat): Macaroon = {
    val newSig = Hmac.compute(sig, caveat.signedBytes)
    Macaroon(location, id, caveats :+ caveat, newSig)
  }

  def addFirstPartyCaveat(predicate: ByteVector): Macaroon = addCaveat(FirstPartyCaveat(predicate))

  def validate(rootKey: ByteVector): Boolean = {
    val expectedSig = caveats.foldLeft(Hmac.compute(rootKey, id)) {
      case (current, caveat) => Hmac.compute(current, caveat.signedBytes)
    }
    expectedSig == sig
  }

}

object Macaroon {

  /**
   * Create a valid macaroon without any caveat.
   *
   * @param location hint to the target’s location.
   * @param rootKey  high-entropy root key.
   * @param id       identifier.
   */
  def apply(location: String, rootKey: ByteVector, id: ByteVector): Macaroon = {
    val sig = Hmac.compute(rootKey, id)
    Macaroon(location, id, Queue.empty, sig)
  }

}
