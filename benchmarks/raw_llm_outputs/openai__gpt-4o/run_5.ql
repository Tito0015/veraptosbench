import solidity

predicate isExternalCallWithUntrustedInput(FunctionCall call) {
  exists(Expr untrustedInput |
    call.getArgument(0) = untrustedInput and
    untrustedInput.getType().hasName("address") and
    untrustedInput.isParameter()
  )
}

predicate isStateMutationAfterExternalCall(FunctionCall call, Assignment assign) {
  assign.getEnclosingCallable() = call.getEnclosingCallable() and
  assign.getLocation().getStartLine() > call.getLocation().getEndLine()
}

from FunctionCall call, Assignment assign
where isExternalCallWithUntrustedInput(call) and isStateMutationAfterExternalCall(call, assign)
select assign, "Avoid state mutation after an external call with untrusted input."
