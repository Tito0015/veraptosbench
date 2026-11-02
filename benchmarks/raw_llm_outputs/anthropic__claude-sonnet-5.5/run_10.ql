import python
import semmle.python.ApiGraphs

/**
 * @name State mutation following an external untrusted interaction
 * @description A public function calls requests/httpx/subprocess and then
 *              writes object state using the result.
 * @kind problem
 * @problem.severity warning
 * @id py/state-write-after-external-call
 */

predicate externalCall(Call c) {
  exists(string m |
    m in ["requests", "httpx", "subprocess"] and
    c = API::moduleImport(m).getAMember().getACall().asExpr()
  )
}

predicate stateTarget(Expr target) {
  target.(Attribute).getObject().(Name).getId() = "self"
  or
  target.(Subscript).getObject().(Attribute).getObject().(Name).getId() = "self"
}

predicate usesResponse(Assign write, Call call) {
  write.getValue().getASubExpression*() = call
  or
  exists(Assign ca, Name v, Name use |
    ca.getValue() = call and
    v = ca.getATarget() and
    use = write.getValue().getASubExpression*() and
    use.getId() = v.getId()
  )
}

from Function f, Call call, Assign write, Expr target
where
  not f.getName().prefix(1) = "_" and
  externalCall(call) and
  call.getScope() = f and
  write.getScope() = f and
  target = write.getATarget() and
  stateTarget(target) and
  usesResponse(write, call) and
  call.getLocation().getStartLine() <= write.getLocation().getStartLine()
select write,
  "Public function '" + f.getName() +
    "' writes state using the result of an external call $@.", call, "here"
