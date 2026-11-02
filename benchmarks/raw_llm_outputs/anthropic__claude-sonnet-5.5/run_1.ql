import python
import semmle.python.ApiGraphs
import semmle.python.dataflow.new.DataFlow

/** A call into requests, httpx or subprocess. */
predicate externalCall(DataFlow::CallCfgNode call) {
  call = API::moduleImport("requests").getAMember().getACall()
  or
  call = API::moduleImport("httpx").getAMember().getACall()
  or
  call = API::moduleImport("subprocess").getAMember().getACall()
}

/** An assignment that writes to an attribute or item (state write). */
predicate stateWrite(Assign a) {
  a.getATarget() instanceof Attribute
  or
  a.getATarget() instanceof Subscript
}

from Function f, DataFlow::CallCfgNode call, Assign a, Expr used
where
  f.getName().charAt(0) != "_" and
  externalCall(call) and
  call.asExpr().getScope() = f and
  a.getScope() = f and
  stateWrite(a) and
  used = a.getValue().getASubExpression*() and
  DataFlow::localFlow(call, DataFlow::exprNode(used)) and
  call.getLocation().getStartLine() < a.getLocation().getStartLine()
select a, "Public function $@ writes state using data from an untrusted external call $@.", f,
  f.getName(), call, "here"
