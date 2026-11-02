import python
from Call c, Assignment a
where c.getFunc().(Name).getId() = "get" and
      (c.getTarget().(Name).getId() = "requests" or c.getTarget().(Name).getId() = "httpx" or c.getTarget().(Name).getId() = "subprocess") and
      a.getLeft() = c.getArgument(0)  // Assuming the response is the first argument
select c, a, "State mutation following an external untrusted interaction"
