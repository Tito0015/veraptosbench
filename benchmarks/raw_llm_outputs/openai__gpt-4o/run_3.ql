import solidity

from FunctionCall fc, Function f, Assignment a
where
  f.isPublic() and
  fc.getEnclosingFunction() = f and
  fc.getTarget().getName() = "call" and
  a.getEnclosingFunction() = f and
  a.getLocation().getStartLine() > fc.getLocation().getEndLine()
select a, "Avoid state mutation after an external call to untrusted input."
