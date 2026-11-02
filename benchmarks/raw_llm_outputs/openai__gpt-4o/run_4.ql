import solidity

predicate isExternalCall(FunctionCall call) {
  call.getTarget().getName() = "external"
}

predicate isStateMutation(Assignment assign) {
  assign.getLeftHandSide() instanceof MemberAccess
}

from FunctionCall call, Assignment assign
where
  isExternalCall(call) and
  isStateMutation(assign) and
  call.getEnclosingCallable() = assign.getEnclosingCallable()
select assign, "State mutation following an external untrusted interaction detected."
