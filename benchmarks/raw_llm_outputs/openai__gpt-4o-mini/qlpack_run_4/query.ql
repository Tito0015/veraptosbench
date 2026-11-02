import python
from Function f, Call c, Assignment a
where f.isPublic() and 
      (c.getFunc().(Name).getId() = "requests.get" or 
       c.getFunc().(Name).getId() = "httpx.get" or 
       c.getFunc().(Name).getId() = "subprocess.run") and 
      a.getValue() = c and 
      a.getTarget().(Name) = f.getName()
select f, "Public function performs external call and writes state."
