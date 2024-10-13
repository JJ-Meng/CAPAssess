set( LLVM_LINK_COMPONENTS
  Support
  )

add_clang_tool(myclang-check
  MyClangCheck.cpp
  )

clang_target_link_libraries(myclang-check
  PRIVATE
  clangAST
  clangBasic
  clangDriver
  clangFrontend
  clangRewriteFrontend
  clangStaticAnalyzerFrontend
  clangTooling
  clangToolingSyntax
  )

install(TARGETS myclang-check RUNTIME DESTINATION bin)
