package com.yourorganization.maven_sample;

import com.github.javaparser.ast.body.FieldDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.body.VariableDeclarator;
import com.github.javaparser.ast.expr.Expression;
import com.github.javaparser.ast.expr.LiteralExpr;
import com.github.javaparser.ast.visitor.VoidVisitorAdapter;
import com.github.javaparser.ast.type.ReferenceType;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Pattern;

public class VariableVisitor extends VoidVisitorAdapter<Void> {
	
    AtomicInteger primitiveTypeCount = new AtomicInteger();
    AtomicInteger compsositeTypeCount = new AtomicInteger();
    
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
    	
    	if(declarator.getParentNode().isPresent())
    	{
    		if(declarator.getParentNode().get() instanceof FieldDeclaration)
    		{
    			FieldDeclaration fd = (FieldDeclaration) declarator.getParentNode().get();
    			if(fd.isFinal())
    			{
    				Expression initializer = declarator.getInitializer().orElse(null);
    				if (initializer != null && initializer instanceof LiteralExpr) 
    				{
                        if (initializer != null && initializer instanceof LiteralExpr) 
                        {
                            String name = declarator.getNameAsString();
                            Number value = parseNumber(((LiteralExpr) initializer).toString());
                            if(value != null)
                            	finalIntegerLiterals.put(name, value);
                        }
    				}
    			}
    		}
    		else if(declarator.getParentNode().get() instanceof MethodDeclaration)
    		{
    			MethodDeclaration md = (MethodDeclaration) declarator.getParentNode().get();
    			if(md.isFinal())
    			{
    				Expression initializer = declarator.getInitializer().orElse(null);
    				if (initializer != null && initializer instanceof LiteralExpr) 
    				{
                        if (initializer != null && initializer instanceof LiteralExpr) 
                        {
                            String name = declarator.getNameAsString();
                            Number value = parseNumber(((LiteralExpr) initializer).toString());
                            if(value != null)
                            	finalIntegerLiterals.put(name, value);
                        }
    				}
    			}
    		}
    	}
    	
        if(declarator.getType().isPrimitiveType()){
            primitiveTypeCount.getAndIncrement();
            
            switch (declarator.getType().asString()) {
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
        }else{
            compsositeTypeCount.getAndIncrement();
            //System.out.println(declarator.getType().asString());
            
            // New switch structure to search for enums, JRE types, and homemade types.
            if(declarator.getType().asString().contains("Enumeration"))
            	enumCount.getAndIncrement();
            else if(isJREClass(declarator.getType().asString(), CodeAnalysis.jreTypeList) && !isJREClass(declarator.getType().asString(), CodeAnalysis.userDefinedTypeNames))
            	JRECount.getAndIncrement();
            else 
            	homemadeCount.getAndIncrement();
        }

    }
    
    private static boolean isJREClass(String className, HashSet<String> uniqueClassNames) {
        for (String name : uniqueClassNames) {
            // Use a regular expression to perform a flexible match
            if (Pattern.compile(Pattern.quote(name), Pattern.CASE_INSENSITIVE).matcher(className).find()) {
                return true;
            }
        }
        return false;
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
