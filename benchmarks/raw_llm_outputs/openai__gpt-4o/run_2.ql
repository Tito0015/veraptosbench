import solidity

predicate isUntrustedCall(FunctionCall call) {
  call.getTarget().getName() = "untrustedFunction"
}

predicate isStateMutation(Assignment assign) {
  assign.getLeftHandSide() instanceof MemberAccess
}

from FunctionCall untrustedCall, Assignment stateMutation
where
  untrustedCall.getEnclosingCallable() = stateMutation.getEnclosingCallable() and
  isUntrustedCall(untrustedCall) and
  isStateMutation(stateMutation) and
  untrustedCall.getLocation().getEndLine() < stateMutation.getLocation().getStartLine()
select stateMutation, "Avoid state mutation after an external call to untrusted input."
