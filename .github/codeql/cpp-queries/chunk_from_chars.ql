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
import semmle.code.cpp.dataflow.new.DataFlow

class ChunkFromChars extends Expr {
  ChunkFromChars() {
    this = any(MacroInvocation mi |
      mi.getOutermostMacroAccess().getMacroName() = "chunk_from_chars"
      /* ignore global static uses of the macro */
      and exists (BlockStmt b | mi.getExpr().getEnclosingBlock() = b)
    ).getExpr()
  }
}

module ChunkFromCharsConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source.asExpr() instanceof ChunkFromChars
  }

  predicate isSink(DataFlow::Node sink) {
    exists(sink.asExpr())
  }

  predicate isBarrierOut(DataFlow::Node node) {
    /* don't track beyond function calls */
    exists(FunctionCall fc | node.asExpr().getParent*() = fc)
  }
}

module ChunkFromCharsFlow = DataFlow::Global<ChunkFromCharsConfig>;
import ChunkFromCharsFlow::PathGraph

BlockStmt enclosingBlock(BlockStmt b) {
  result = b.getEnclosingBlock()
}

from ChunkFromCharsFlow::PathNode source, ChunkFromCharsFlow::PathNode sink
where
  ChunkFromCharsFlow::flowPath(source, sink)
  and not source.getNode().asExpr().getEnclosingBlock() = enclosingBlock*(sink.getNode().asExpr().getEnclosingBlock())
select source, source, sink, "Invalid use of chunk_from_chars() result in sibling/parent block."
