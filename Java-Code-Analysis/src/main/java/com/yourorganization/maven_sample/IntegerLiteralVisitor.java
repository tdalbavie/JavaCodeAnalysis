package com.yourorganization.maven_sample;

import com.github.javaparser.ast.body.VariableDeclarator;
import com.github.javaparser.ast.expr.Expression;
import com.github.javaparser.ast.expr.IntegerLiteralExpr;
import com.github.javaparser.ast.expr.NameExpr;
import com.github.javaparser.ast.visitor.VoidVisitorAdapter;

import java.util.concurrent.atomic.AtomicInteger;

public class IntegerLiteralVisitor extends VoidVisitorAdapter<Void> {
	
	AtomicInteger countConstants = new AtomicInteger();
	AtomicInteger countConstantsInRange = new AtomicInteger();
	AtomicInteger countConstantsInDeclarations = new AtomicInteger();
	
	@Override
	public void visit(IntegerLiteralExpr ile, Void arg) 
	{
		if (isWithinRange(ile.asNumber()))
			countConstantsInRange.getAndIncrement();
		
		countConstants.getAndIncrement();
	}
	
	@Override
	public void visit(NameExpr ne, Void arg)
	{
		String constantName = ne.getNameAsString();
		if(CodeAnalysis.globalFinalIntegerLiterals.containsKey(constantName))
		{
			Number constantValue = CodeAnalysis.globalFinalIntegerLiterals.get(constantName);
			if (isWithinRange(constantValue))
				countConstantsInRange.getAndIncrement();
			
			countConstants.getAndIncrement();
		}
	}
	
    @Override
    public void visit(VariableDeclarator vd, Void arg) {
        super.visit(vd, arg);
        Expression initializer = vd.getInitializer().orElse(null);
        if (initializer instanceof IntegerLiteralExpr || (initializer instanceof NameExpr && 
            CodeAnalysis.globalFinalIntegerLiterals.containsKey(((NameExpr) initializer).getNameAsString()))) {
            countConstantsInDeclarations.getAndIncrement();
        }
    }
	
    private boolean isWithinRange(Number number) 
    {
        double doubleValue = number.doubleValue(); 

        double lowerBound = -32.0;
        double upperBound = 32.0;

        return doubleValue >= lowerBound && doubleValue <= upperBound;
    }

}
