/**
 * @kind problem
 * @id veraptosbench/native-python-function
 * @name Function definitions
 * @problem.severity recommendation
 */

import python

from Function f
where exists(f.getLocation().getFile().getRelativePath())
select f, "function " + f.getName()
