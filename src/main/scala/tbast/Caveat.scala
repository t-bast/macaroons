package tbast

import scodec.bits.ByteVector

/**
 * Caveats are predicates that restrict a macaroon’s authority, as well as the context in which it may be successfully
 * used.
 */
sealed trait Caveat {
  /** Caveat identifier (or encoded predicate). */
  val id: ByteVector

  /** Bytes that should be included in the chained-MAC signature. */
  def signedBytes: ByteVector
}

/**
 * First-party caveats are predicates that restrict a macaroon’s capabilities at the target service (service that mints
 * the macaroon).
 *
 * @param predicate encoded predicate that can be decoded and applied to the context of an incoming request.
 */
case class FirstPartyCaveat(predicate: ByteVector) extends Caveat {

  override val id = predicate

  override def signedBytes: ByteVector = predicate

}

/**
 * Third-party caveats allow a macaroon to specify and require any number of holder-of-key proofs to be presented with
 * authorized requests.
 *
 * They allow a target service to delegate part of the request authorization to other, unrelated services.
 *
 * @param location hint to a discharge location (principal that can validate the caveat).
 * @param id       caveat identifier.
 * @param keyId    verification-key identifier.
 */
case class ThirdPartyCaveat(location: String, id: ByteVector, keyId: ByteVector) extends Caveat {
  override def signedBytes: ByteVector = keyId ++ id
}
