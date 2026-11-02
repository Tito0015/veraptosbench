import python
from Call c, Assignment a
where (c.getFunc().getName() = "requests" or c.getFunc().getName() = "httpx" or c.getFunc().getName() = "subprocess")
  and a.getRight() = c
  and a.getLeft().(Variable) = a.getEnclosingFunction().getAChildOf().(Variable)
select c, "State mutation following an external untrusted interaction"
