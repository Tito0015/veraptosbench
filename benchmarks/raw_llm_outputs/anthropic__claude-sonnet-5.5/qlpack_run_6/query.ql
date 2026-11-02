import python
import semmle.python.ApiGraphs
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

from
  Function f, string mod, API::CallNode call, AssignStmt a, Attribute target,
  DataFlow::Node val
where
  mod in ["requests", "httpx", "subprocess"] and
  call = API::moduleImport(mod).getAMember().getACall() and
  call.getScope() = f and
  a.getScope() = f and
  not f.getName().charAt(0) = "_" and
  a.getATarget() = target and
  val.asExpr() = a.getValue() and
  TaintTracking::localTaint(call, val) and
  call.getLocation().getStartLine() < a.getLocation().getStartLine()
select a,
  "Public function '" + f.getName() + "' writes state after an external call to " + mod +
    " (line " + call.getLocation().getStartLine().toString() + ") using its result."
