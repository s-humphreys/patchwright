// Package celx holds small helpers for compiling and evaluating the CEL
// expressions used by patchwright's ownership and policy rules.
package celx

import (
	"fmt"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common/types/ref"
)

// CompileBool compiles expr against env and requires it to yield a bool.
func CompileBool(env *cel.Env, expr string) (cel.Program, error) {
	return compile(env, expr, cel.BoolType)
}

// CompileString compiles expr against env and requires it to yield a string.
func CompileString(env *cel.Env, expr string) (cel.Program, error) {
	return compile(env, expr, cel.StringType)
}

func compile(env *cel.Env, expr string, want *cel.Type) (cel.Program, error) {
	ast, iss := env.Compile(expr)
	if iss != nil && iss.Err() != nil {
		return nil, iss.Err()
	}
	if got := ast.OutputType(); !got.IsExactType(want) {
		return nil, fmt.Errorf("expression must evaluate to %s, but returns %s", want, got)
	}
	return env.Program(ast)
}

// EvalBool runs a program expected to return a bool.
func EvalBool(prg cel.Program, activation map[string]any) (bool, error) {
	out, err := eval(prg, activation)
	if err != nil {
		return false, err
	}
	b, ok := out.Value().(bool)
	if !ok {
		return false, fmt.Errorf("expected bool result, got %T", out.Value())
	}
	return b, nil
}

// EvalString runs a program expected to return a string.
func EvalString(prg cel.Program, activation map[string]any) (string, error) {
	out, err := eval(prg, activation)
	if err != nil {
		return "", err
	}
	s, ok := out.Value().(string)
	if !ok {
		return "", fmt.Errorf("expected string result, got %T", out.Value())
	}
	return s, nil
}

func eval(prg cel.Program, activation map[string]any) (ref.Val, error) {
	out, _, err := prg.Eval(activation)
	if err != nil {
		return nil, err
	}
	return out, nil
}
