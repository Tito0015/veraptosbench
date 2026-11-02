import python
import semmle.python.ApiGraphs
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

/** A call into requests, httpx or subprocess. */
DataFlow::CallCfgNode externalCall() {
  result =
    API::moduleImport(["requests", "httpx", "subprocess"]).getAMember().getACall()
}

module ExternalToStateConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n = externalCall() }

  predicate isSink(DataFlow::Node n) {
    exists(DataFlow::AttrWrite w |
      w.getValue() = n and
      w.getObject().asExpr().(Name).getId() = "self"
    )
  }

  predicate isAdditionalFlowStep(DataFlow::Node a, DataFlow::Node b) {
    // e.g. response.json(), response.text.strip(), proc.communicate()
    b.(DataFlow::MethodCallNode).getObject() = a
  }
}

module ExternalToStateFlow = TaintTracking::Global<ExternalToStateConfig>;

from
  Function f, DataFlow::Node src, DataFlow::Node sink
where
  ExternalToStateFlow::flow(src, sink) and
  src.getScope() = f and
  sink.getScope() = f and
  not f.getName().matches("\\_%") and
  src.getLocation().getStartLine() <= sink.getLocation().getStartLine()
select sink,
  "Public function '" + f.getName() +
    "' writes object state using data from an external call (requests/httpx/subprocess) made at $@.",
  src, "this call"
