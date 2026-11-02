import python
from Function f, Call c, Assignment a
where f.isPublic() and
      (c.getFunc().(Name).getId() = "requests.get" or
       c.getFunc().(Name).getId() = "httpx.get" or
       c.getFunc().(Name).getId() = "subprocess.run") and
      a.getLeft() = f.getBody().(Assignment).getLeft() and
      a.getRight() = c
select f, "Public function performs an external call to untrusted input and then writes contract state."
