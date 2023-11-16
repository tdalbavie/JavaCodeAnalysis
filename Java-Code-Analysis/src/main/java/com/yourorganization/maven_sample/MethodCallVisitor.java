package com.yourorganization.maven_sample;

import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.Node;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.visitor.VoidVisitorAdapter;

import java.util.*;

public class MethodCallVisitor extends VoidVisitorAdapter<Void> {

    private Set<MethodDeclaration> visitedMethods = new HashSet<>();
    int recursiveCount = 0;
    int nonRecursiveCount = 0;

    @Override
    public void visit(MethodDeclaration method, Void arg) {
        visitedMethods.add(method);
        super.visit(method, arg);
    }

    @Override
    public void visit(MethodCallExpr call, Void arg) {
        //recursively traverse the AST
        super.visit(call, arg);

        // Find the method in which this call is made
        Optional<MethodDeclaration> currentMethod = call.findAncestor(MethodDeclaration.class);
        
        if (currentMethod.isEmpty())
        	return;
        
        String methodName = call.getNameAsString();
        for (MethodDeclaration visitedMethod : visitedMethods) {
        	// if (visitedMethod.getNameAsString().equals(methodName) && visitedMethod != call.findAncestor(MethodDeclaration.class).get())
            if (visitedMethod.getNameAsString().equals(methodName)) {
                // This is a recursive method call
            	if (visitedMethod.equals(currentMethod.get())) {
                    recursiveCount++;
                    return;
                }
            }
        }
        nonRecursiveCount++;
    }
}