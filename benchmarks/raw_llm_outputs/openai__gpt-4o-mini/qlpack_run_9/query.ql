import python
from Function f, Call c, Assignment a
where f.isPublic() and
      c.getFunc().(Name).getId() in ["get", "post"] and
      c.getTarget().(Name).getId() in ["requests", "httpx", "subprocess"] and
      a.getValue() = c and
      a.getLeft() instanceof Name
select f, "State mutation following an external untrusted interaction detected."
