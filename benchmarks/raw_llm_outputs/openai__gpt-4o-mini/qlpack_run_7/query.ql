import python
from Call c, Assignment a
where (c.getFunc().(Name).getId() = "requests.get" or 
       c.getFunc().(Name).getId() = "httpx.get" or 
       c.getFunc().(Name).getId() = "subprocess.run")
  and a.getAnOperand() = c.getArgument(0)
  and a.getEnclosingFunction() = c.getEnclosingFunction()
select c, "External call followed by state mutation"
