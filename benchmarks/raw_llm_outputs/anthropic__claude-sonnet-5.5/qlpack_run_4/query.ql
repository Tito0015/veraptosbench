import python
import semmle.python.ApiGraphs
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

/** A call into an external, untrusted interaction: requests, httpx or subprocess. */
class ExternalCall extends DataFlow::CallCfgNode {
  ExternalCall() {
    this = API::moduleImport("requests").getAMember().getACall()
    or
    this = API::moduleImport("httpx").getAMember().getACall()
    or
    this = API::moduleImport("subprocess").getAMember().getACall()
  }
}

from ExternalCall call, Function f, AssignStmt a, Expr target
where
  call.getScope() = f and
  a.getScope() = f and
  f.getName().prefix(1) != "_" and
  target = a.getATarget() and
  (target instanceof Attribute or target instanceof Subscript) and
  call.getLocation().getStartLine() < a.getLocation().getStartLine() and
  TaintTracking::localTaint(call, DataFlow::exprNode(a.getValue()))
select a,
  "Public function '" + f.getName() +
    "' writes state using a value derived from an external call $@.", call, "here"
