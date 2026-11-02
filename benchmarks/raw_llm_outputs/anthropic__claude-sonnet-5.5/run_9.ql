import python

/** A call to requests.*, httpx.* or subprocess.* */
predicate externalCall(Call c) {
  exists(Attribute a, Name m |
    a = c.getFunc() and
    m = a.getObject() and
    m.getId() in ["requests", "httpx", "subprocess"]
  )
}

from Function f, Assign src, Call c, Name v, Assign sink, Attribute target, Name use
where
  // public function
  f.getName().prefix(1) != "_" and
  // external call whose result is bound to a local variable
  src.getScope() = f and
  src.getValue() = c and
  externalCall(c) and
  src.getATarget() = v and
  // later state write on self that uses that result
  sink.getScope() = f and
  sink.getATarget() = target and
  target.getObject().(Name).getId() = "self" and
  use.getId() = v.getId() and
  sink.getValue().getASubExpression*() = use and
  src.getLocation().getStartLine() < sink.getLocation().getStartLine()
select sink,
  "State is written using the result of an external call (requests/httpx/subprocess) made earlier in public function '"
    + f.getName() + "'."
