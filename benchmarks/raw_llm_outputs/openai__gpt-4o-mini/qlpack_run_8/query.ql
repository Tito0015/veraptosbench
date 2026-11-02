import python
from Call c, Function f, Assignment a
where (c.getFunc().getName() = "requests.get" or c.getFunc().getName() = "httpx.get" or c.getFunc().getName() = "subprocess.run")
  and a.getRight() = c
  and a.getLeft().(Name).getId() = "..."
select a, "State mutation following an external untrusted interaction"
