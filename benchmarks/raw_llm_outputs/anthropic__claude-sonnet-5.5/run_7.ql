/**
 * @name State write after external untrusted call in public function
 * @description A public function calls requests/httpx/subprocess and then
 *              assigns to object or container state using data derived from
 *              the result.
 * @kind problem
 * @problem.severity warning
 * @id py/state-write-after-untrusted-external-call
 */

import python
import semmle.python.ApiGraphs
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

from
  Function f, API::CallNode call, AssignStmt a, Expr target, Expr sub, string mod
where
  mod in ["requests", "httpx", "subprocess"] and
  call = API::moduleImport(mod).getAMember().getACall() and
  not f.getName().prefix(1) = "_" and
  call.getNode().getScope() = f and
  a.getScope() = f and
  target = a.getATarget() and
  (target instanceof Attribute or target instanceof Subscript) and
  sub = a.getValue().getASubExpression*() and
  TaintTracking::localTaint(call, DataFlow::exprNode(sub)) and
  call.getLocation().getStartLine() <= a.getLocation().getStartLine()
select a,
  "Public function '" + f.getName() + "' writes state using the result of an external " + mod +
    " call $@.", call, "made here"
