"""Round-8 second-order code execution fixture (eval/exec on self.<attr>)."""


class DynamicConfig:
    expression = ""
    code = ""

    def evaluate(self):
        """BAD: eval() on a persisted model attribute."""
        return eval(self.expression)

    def execute(self):
        """BAD: exec() on a persisted model attribute."""
        exec(self.code)

    def compile_it(self):
        """BAD: compile() on a persisted model attribute."""
        return compile(self.expression, "<dynamic>", "exec")


class SafeEvaluator:
    def literal(self):
        """GOOD: static string literal argument."""
        return eval("1 + 1")

    def trusted(self):
        """GOOD: exec of a fixed, trusted program string."""
        exec("print('hi')")
