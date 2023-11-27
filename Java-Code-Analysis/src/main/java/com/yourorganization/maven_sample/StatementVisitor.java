package com.yourorganization.maven_sample;

import com.github.javaparser.ast.visitor.VoidVisitorAdapter;
import com.github.javaparser.ast.expr.SwitchExpr;
import com.github.javaparser.ast.stmt.*;

import java.util.concurrent.atomic.AtomicInteger;

public class StatementVisitor extends VoidVisitorAdapter<Void>{
	
	AtomicInteger ifCount = new AtomicInteger();
	AtomicInteger whileCount = new AtomicInteger();
	AtomicInteger forCount = new AtomicInteger();
	AtomicInteger enhancedForCount = new AtomicInteger();
	AtomicInteger caseCount = new AtomicInteger();
	
	@Override
	public void visit(IfStmt is, Void arg)
	{
		super.visit(is, arg);
		ifCount.getAndIncrement();
	}

	@Override
	public void visit(WhileStmt ws, Void arg)
	{
		super.visit(ws, arg);
		whileCount.getAndIncrement();
	}
	
	@Override
	public void visit(DoStmt ws, Void arg)
	{
		super.visit(ws, arg);
		whileCount.getAndIncrement();
	}
	
	@Override
	public void visit(ForStmt fs, Void arg)
	{
		super.visit(fs, arg);
		forCount.getAndIncrement();
	}
	
	@Override
	public void visit(ForEachStmt fes, Void arg)
	{
		super.visit(fes, arg);
		enhancedForCount.getAndIncrement();
	}
	
	@Override
	public void visit(SwitchStmt ss, Void arg)
	{
		super.visit(ss, arg);
		caseCount.getAndAdd(ss.getEntries().size());
	}
	
    @Override
    public void visit(SwitchExpr se, Void arg) 
    {
        super.visit(se, arg);
        caseCount.getAndAdd(se.getEntries().size());
    }
}
