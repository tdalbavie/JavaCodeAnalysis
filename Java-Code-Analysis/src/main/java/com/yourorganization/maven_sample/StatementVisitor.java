package com.yourorganization.maven_sample;

import com.github.javaparser.ast.visitor.VoidVisitorAdapter;
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
		ifCount.getAndIncrement();
	}

	@Override
	public void visit(WhileStmt ws, Void arg)
	{
		whileCount.getAndIncrement();
	}
	
	@Override
	public void visit(ForStmt fs, Void arg)
	{
		forCount.getAndIncrement();
	}
	
	@Override
	public void visit(ForEachStmt fes, Void arg)
	{
		enhancedForCount.getAndIncrement();
	}
	
	@Override
	public void visit(SwitchStmt ss, Void arg)
	{
		caseCount.getAndAdd(ss.getEntries().size());
	}
}
