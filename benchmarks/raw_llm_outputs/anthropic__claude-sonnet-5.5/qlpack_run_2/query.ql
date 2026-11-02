import python
import semmle.python.ApiGraphs
import semmle.python.dataflow.new.DataFlow

/** A call to requests, httpx or subprocess, i.e. an external untrusted interaction. */
predicate externalCall(DataFlow::CallCfgNode c) {
  c =
    API::moduleImport("requests")
        .getMember(["get", "post", "put", "delete", "patch", "head", "options", "request"])
        .getACall()
  or
  c =
    API::moduleImport("httpx")
        .getMember(["get", "post", "put", "delete", "patch", "head", "options", "request"])
        .getACall()
  or
  c =
    API::moduleImport("subprocess")
        .getMember(["run", "call", "check_call", "check_output", "Popen"])
        .getACall()
}

/** A state write: assignment to an attribute (or an item of an attribute) of an object. */
predicate stateTarget(Expr target) {
  target instanceof Attribute
  or
  target.(Subscript).getObject() instanceof Attribute
}

from Function f, DataFlow::CallCfgNode call, AssignStmt assign, Expr target, Expr used
where
  f.getName().prefix(1) != "_" and
  externalCall(call) and
  call.getScope() = f and
  assign.getScope() = f and
  target = assign.getATarget() and
  stateTarget(target) and
  used = assign.getValue().getASubExpression*() and
  DataFlow::localFlow(call, DataFlow::exprNode(used)) and
  call.getLocation().getStartLine() < assign.getLocation().getStartLine()
select assign,
  "State is written in public function '" + f.getName() +
    "' using the result of an external call $@ (requests/httpx/subprocess).", call,
  "made here"
