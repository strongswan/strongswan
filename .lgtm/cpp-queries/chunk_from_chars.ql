/**
 * @name Invalid use of chunk_from_chars() macro
 * @description The chunk_from_chars() macro creates a temporary chunk_t, which
 *              is not defined outside of the block in which it has been used,
 *              therefore, compilers might optimize out the assignment.
 * @kind path-problem
 * @problem.severity error
 * @id strongswan/invalid-chunk-from-chars
 * @tags correctness
 * @precision very-high
 */
import cpp
import DataFlow::PathGraph
import semmle.code.cpp.dataflow.DataFlow

class ChunkFromChars extends Expr {
  ChunkFromChars() {
    this = any(MacroInvocation mi |
      mi.getOutermostMacroAccess().getMacroName() = "chunk_from_chars"
      /* ignore global static uses of the macro */
      and exists (BlockStmt b | mi.getExpr().getEnclosingBlock() = b)
    ).getExpr()
  }
}

class ChunkFromCharsUsage extends DataFlow::Configuration {
  ChunkFromCharsUsage() { this = "ChunkFromCharsUsage" }

  override predicate isSource(DataFlow::Node source) {
    source.asExpr() instanceof ChunkFromChars
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(sink.asExpr())
  }

  override predicate isBarrierOut(DataFlow::Node node) {
    /* don't track beyond function calls */
    exists(FunctionCall fc | node.asExpr().getParent*() = fc)
  }
}

BlockStmt enclosingBlock(BlockStmt b) {
  result = b.getEnclosingBlock()
}

from ChunkFromCharsUsage usage, DataFlow::PathNode source, DataFlow::PathNode sink
where
  usage.hasFlowPath(source, sink)
  and not source.getNode().asExpr().getEnclosingBlock() = enclosingBlock*(sink.getNode().asExpr().getEnclosingBlock())
select source, source, sink, "Invalid use of chunk_from_chars() result in sibling/parent block."
