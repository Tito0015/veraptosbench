import python
from Function f, Call c, Assignment a
where f.isPublic() and
      c.getFunc().(Name).getId() in ["get", "run"] and
      c.getArgument(0).(Name).getId() in ["requests", "httpx", "subprocess"] and
      a.getTarget() = f and
      a.getValue() = c
select f, "Public function performs an external call to untrusted input and then writes contract state."
