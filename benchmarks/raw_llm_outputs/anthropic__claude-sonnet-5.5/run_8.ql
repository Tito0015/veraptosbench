import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

predicate externalCall(Call c) {
  exists(Attribute attr, Name base |
    attr = c.getFunc() and
    base = attr.getObject() and
    base.getId() in ["requests", "httpx", "subprocess"]
  )
}

from Function f, Call c, Assign a, Expr target
where
  f.getName().charAt(0) != "_" and
  c.getScope() = f and
  a.getScope() = f and
  externalCall(c) and
  target = a.getATarget() and
  (target instanceof Attribute or target instanceof Subscript) and
  TaintTracking::localTaint(DataFlow::exprNode(c), DataFlow::exprNode(a.getValue()))
select a,
  "Public function '" + f.getName() +
    "' writes state using data from an external untrusted call $@.", c, "here"
