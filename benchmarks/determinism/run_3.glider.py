from glider import *

def query():
    # Selector 0xa8f51e19 — pull
    # Vulnerability class: UncheckedLowLevelCall
    return (
        Functions()
        .with_name("pull")
        .with_one_property([MethodProp.EXTERNAL, MethodProp.PUBLIC])
        .instructions()
        .with_callee_name("call")
        .exec(100)
    )
