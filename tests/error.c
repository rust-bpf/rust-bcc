int trace_return(struct pt_regs *ctx)
{
  // Infinite loop, this should fail the verifier.
  for (;;) {}
  return 0;
}

