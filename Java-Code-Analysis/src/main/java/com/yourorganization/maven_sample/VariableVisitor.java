package com.yourorganization.maven_sample;

import com.github.javaparser.ast.body.FieldDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.body.VariableDeclarator;
import com.github.javaparser.ast.expr.Expression;
import com.github.javaparser.ast.expr.LiteralExpr;
import com.github.javaparser.ast.expr.VariableDeclarationExpr;
import com.github.javaparser.ast.visitor.VoidVisitorAdapter;
import com.github.javaparser.resolution.types.ResolvedType;
import com.github.javaparser.ast.type.ReferenceType;
import com.github.javaparser.ast.type.ArrayType;
import com.github.javaparser.ast.type.Type;
import com.github.javaparser.resolution.declarations.ResolvedReferenceTypeDeclaration;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Pattern;

public class VariableVisitor extends VoidVisitorAdapter<Void> {
	
    AtomicInteger primitiveTypeCount = new AtomicInteger();
    AtomicInteger compositeTypeCount = new AtomicInteger();
    
    // Will be used to further break down composite types.
    AtomicInteger enumCount = new AtomicInteger();
    AtomicInteger JRECount = new AtomicInteger();
    AtomicInteger homemadeCount = new AtomicInteger();

    AtomicInteger booleanCount = new AtomicInteger();
    AtomicInteger byteCount = new AtomicInteger();
    AtomicInteger shortCount = new AtomicInteger();
    AtomicInteger charCount = new AtomicInteger();
    AtomicInteger intCount = new AtomicInteger();
    AtomicInteger longCount = new AtomicInteger();
    AtomicInteger floatCount = new AtomicInteger();
    AtomicInteger doubleCount = new AtomicInteger();
    
    // This will hold all the final variables set equal to a number for use in IntegerLiteralVisitor.
    HashMap<String, Number> finalIntegerLiterals = new HashMap<String, Number>();

    @Override
    public void visit(VariableDeclarator declarator, Void arg) {
        //System.out.println(declarator.getType());
    	
        // Check if the parent node is a FieldDeclaration or VariableDeclarationExpr
        declarator.getParentNode().ifPresent(parentNode -> {
            boolean isFinal = false;

            if (parentNode instanceof FieldDeclaration) {
                // Check if it's a final field
                isFinal = ((FieldDeclaration) parentNode).isFinal();
            } else if (parentNode instanceof VariableDeclarationExpr) {
                // Check if it's a final local variable
                isFinal = ((VariableDeclarationExpr) parentNode).isFinal();
            }

            // Process final variables
            if (isFinal) {
                Expression initializer = declarator.getInitializer().orElse(null);
                if (initializer instanceof LiteralExpr) {
                    String name = declarator.getNameAsString();
                    Number value = parseNumber(((LiteralExpr) initializer).toString());
                    if (value != null) {
                        finalIntegerLiterals.put(name, value);
                    }
                }
            }
        });
    	
        
        if(declarator.getType().isPrimitiveType()){
            primitiveTypeCount.getAndIncrement();
            String type = declarator.getType().asString();
            
            switch (type) {
                case "boolean":
                    booleanCount.getAndIncrement();
                    break;

                case "byte":
                    byteCount.getAndIncrement();
                    break;

                case "short":
                    shortCount.getAndIncrement();
                    break;

                case "char":
                    charCount.getAndIncrement();
                    break;

                case "int":
                    intCount.getAndIncrement();
                    break;

                case "long":
                    longCount.getAndIncrement();

                    break;
                case "double":
                    doubleCount.getAndIncrement();
                    break;

                case "float":
                    floatCount.getAndIncrement();
                    break;
            }
        }
        
        else
        {
            if(declarator.getType().isArrayType()) {
                ArrayType arrayType = declarator.getType().asArrayType();
                Type componentType = arrayType.getComponentType();
                
                // Deals with primitive arrays.
                if (componentType.isPrimitiveType()) {
                	primitiveTypeCount.getAndIncrement();
                	String type = componentType.asString();
                    switch (type) {
                    case "boolean":
                        booleanCount.getAndIncrement();
                        break;

                    case "byte":
                        byteCount.getAndIncrement();
                        break;

                    case "short":
                        shortCount.getAndIncrement();
                        break;

                    case "char":
                        charCount.getAndIncrement();
                        break;

                    case "int":
                        intCount.getAndIncrement();
                        break;

                    case "long":
                        longCount.getAndIncrement();

                        break;
                    case "double":
                        doubleCount.getAndIncrement();
                        break;

                    case "float":
                        floatCount.getAndIncrement();
                        break;
                    }
                    return;
                }
            }
            
        	try
        	{
	            compositeTypeCount.getAndIncrement();
	            //System.out.println(declarator.getType().asString());
	            
	            ResolvedType resolvedType = declarator.getType().resolve();
	
	            if (resolvedType.isReferenceType()) {
	                ResolvedReferenceTypeDeclaration typeDeclaration = resolvedType.asReferenceType().getTypeDeclaration().get();
	
	                if (typeDeclaration.isEnum()) {
	                    enumCount.getAndIncrement();
	                } else if (isJREClass(typeDeclaration.getQualifiedName(), CodeAnalysis.jreTypeList) && 
	                           !isJREClass(typeDeclaration.getQualifiedName(), CodeAnalysis.userDefinedTypeNames)) {
	                    JRECount.getAndIncrement();
	                } else {
	                    homemadeCount.getAndIncrement();
	                }
	            }
        	}
        	// In case it fails it will still try to count JRE or homemade classes, try block is purely for enum counting.
        	catch (Exception e)
        	{
                if(isJREClass(declarator.getType().asString(), CodeAnalysis.jreTypeList) && !isJREClass(declarator.getType().asString(), CodeAnalysis.userDefinedTypeNames))
                	JRECount.getAndIncrement();
                else 
                	homemadeCount.getAndIncrement();
        	}
        }

    }
    
    private static boolean isJREClass(String className, HashSet<String> uniqueClassNames) {
        // Remove generic type parameters and array notations.
    	String baseClassName = className.replaceAll("<.*>", "").replaceAll("\\[.*\\]", "");

        return uniqueClassNames.contains(baseClassName);
    }
    
    private static Number parseNumber(String value) {
        try {
            if (value.contains(".")) {
                return Double.parseDouble(value);
            } else {
                return Integer.parseInt(value);
            }
        } catch (NumberFormatException e) {
            // Handle parsing errors here (e.g., non-numeric literals)
            return null; // You might want to return a special value or handle this differently
        }
    }

}
