/**
 * @name State mutation following an external untrusted interaction
 * @description A public function calls requests, httpx, or subprocess and then
 *              assigns state (an attribute or a declared global) using a value
 *              derived from the result.
 * @kind problem
 * @problem.severity warning
 * @id py/state-mutation-after-external-call
 */

import python
import semmle.python.ApiGraphs
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

/** A call into requests, httpx, or subprocess. */
predicate externalCall(DataFlow::CallCfgNode call) {
  call = API::moduleImport("requests").getAMember().getACall()
  or
  call = API::moduleImport("httpx").getAMember().getACall()
  or
  call = API::moduleImport("subprocess").getAMember().getACall()
}

/** An assignment that writes persistent state from within function `f`. */
predicate stateWrite(Function f, AssignStmt a) {
  a.getScope() = f and
  (
    a.getATarget() instanceof Attribute
    or
    exists(Name n, Global g |
      n = a.getATarget() and
      g.getScope() = f and
      g.getAName() = n.getId()
    )
  )
}

from Function f, DataFlow::CallCfgNode call, AssignStmt a, DataFlow::Node value
where
  not f.getName().prefix(1) = "_" and
  externalCall(call) and
  call.getScope() = f and
  stateWrite(f, a) and
  value = DataFlow::exprNode(a.getValue()) and
  TaintTracking::localTaint(call, value) and
  call.getLocation().getStartLine() <= a.getLocation().getStartLine()
select a,
  "Public function '" + f.getName() +
    "' writes state using the result of an external call $@.", call.getNode(),
  "here"
