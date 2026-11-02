import solidity

class ExternalCallAfterStateMutation extends Expr {
  ExternalCallAfterStateMutation() {
    exists(FunctionCall call, Assignment assign |
      call.getEnclosingCallable() = assign.getEnclosingCallable() and
      call.getEnclosingCallable().getVisibility() = "public" and
      call.getTarget().getType().hasName("address") and
      assign.getLeft().getType().hasName("state") and
      assign.getLocation().getStartLine() > call.getLocation().getStartLine()
    )
  }
}

from ExternalCallAfterStateMutation e
select e, "State mutation following an external untrusted interaction."
