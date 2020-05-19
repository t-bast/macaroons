package tbast

import org.scalatest.funspec.AnyFunSpec
import tbast.Macaroons._

class MacaroonsSpec extends AnyFunSpec {

  describe("macaroons") {
    it("should say hello") {
      assert(hello() === "hello")
    }
  }

}
