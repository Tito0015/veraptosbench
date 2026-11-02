import python
from Call c, Assignment a
where c.getFunc().(Name).getId() = "get" and
      c.getReceiver().(Name).getId() = "requests" and
      a.getValue() = c
select c, "State mutation following an external untrusted interaction detected."
