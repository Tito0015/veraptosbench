import python
from Function f, Call c, Assignment a
where 
  f.isPublic() and 
  (c.getFunc().(Name).getName() = "get" and (c.getTarget().(Name).getName() = "requests" or c.getTarget().(Name).getName() = "httpx" or c.getTarget().(Name).getName() = "subprocess")) and 
  a.getValue() = c and 
  a.getTarget().(Name).getName() = f.getName()
select f, "State mutation following an external untrusted interaction detected."
