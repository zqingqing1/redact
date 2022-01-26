# redact
This module used to redact non snapshot value, and keep the value that has tagVal "snapshot"

eg:
type Test struct{
    A string `redact:"snapshot"`
    B string
}

t := Test{
    A: "a",
    B: "b",
}

when doing redact.Snapshot(test), the t.A is still having value "a", but t.B will be "NONSNAPSHOT".