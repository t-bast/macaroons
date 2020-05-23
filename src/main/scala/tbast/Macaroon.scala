package tbast

import scodec.bits.ByteVector

import scala.collection.immutable.Queue
import scala.util.{Failure, Success}

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

  /**
   * Add a first-party caveat. This predicate should only restrict the scope of the macaroon, not extend it.
   *
   * @param predicate caveat predicate.
   */
  def addFirstPartyCaveat(predicate: ByteVector): Macaroon = addCaveat(FirstPartyCaveat(predicate))

  /**
   * Add a third-party caveat.
   *
   * The third-party service must be able to find the caveatRootKey from the caveatId: it will only receive the caveatId
   * and must be able to generate a discharge macaroon using caveatRootKey as root.
   * As the first-party rootKey, this can be done by using a reference to a database mapping at the third-party's site,
   * or instructions on how to derive the key from a shared private key. Another possibility is to directly encrypt
   * caveatRootKey inside caveatId with a known public key held by the third-party service.
   *
   * @param location      hint to the third-party's location (will be used by the client to ask for a discharge).
   * @param caveatRootKey root key that will be used when creating the discharge macaroon.
   * @param caveatId      encrypted predicate that the third-party service will validate; used as the top-level caveat
   *                      in the discharge macaroon.
   */
  def addThirdPartyCaveat(location: String, caveatRootKey: ByteVector, caveatId: ByteVector): Option[Macaroon] = {
    Cipher.encrypt(sig, caveatRootKey) match {
      case Success(keyId) => Some(addCaveat(ThirdPartyCaveat(location, caveatId, keyId)))
      case Failure(_) => None
    }
  }

  private def bindForRequest(thirdPartySig: ByteVector): ByteVector = Hmac.compute(sig, thirdPartySig)

  /**
   * Once all discharges have been acquired from third-party services, finalize the macaroon before sending it to the
   * target service for validation.
   *
   * @param discharges discharge macaroons for each third-party caveat.
   * @return the discharge macaroons updated to be bound to the current macaroon.
   */
  def prepareForRequest(discharges: Set[Macaroon]): Set[Macaroon] = {
    discharges.map(discharge => discharge.copy(sig = bindForRequest(discharge.sig)))
  }

  private def validate(topLevelMacaroon: Macaroon, rootKey: ByteVector, dischargeMacaroons: Set[Macaroon]): Boolean = {
    val (expectedSig, caveatsOk) = caveats.foldLeft((Hmac.compute(rootKey, id), true)) {
      case ((currentSig, currentOk), caveat) =>
        val nextSig = Hmac.compute(currentSig, caveat.signedBytes)
        val nextOk = currentOk && (caveat match {
          case FirstPartyCaveat(predicate) => true
          case ThirdPartyCaveat(_, id, keyId) => dischargeMacaroons.find(_.id == id).flatMap(discharge => {
            Cipher.decrypt(currentSig, keyId).toOption.map(thirdPartyRootKey => {
              discharge.validate(topLevelMacaroon, thirdPartyRootKey, dischargeMacaroons)
            })
          }).getOrElse(false)
        })
        (nextSig, nextOk)
    }
    val sigOk = if (topLevelMacaroon == this) sig == expectedSig else sig == topLevelMacaroon.bindForRequest(expectedSig)
    caveatsOk && sigOk
  }

  def validate(rootKey: ByteVector, dischargeMacaroons: Set[Macaroon]): Boolean = {
    validate(this, rootKey, dischargeMacaroons)
  }

}

object Macaroon {

  /**
   * Create a valid macaroon without any caveat.
   *
   * The service minting the macaroon should be able to retrieve the root key based on the macaroon id.
   * A mapping may be saved in a database, or the id could directly contain information that can be used to re-generate
   * the root key (for example, derivation path or nonce to use with a private, master root key).
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
