int __fastcall main(int argc, const char **argv, const char **envp)
{
  void *buf; // [rsp+0h] [rbp-10h]

  init(argc, argv, envp);
  buf = mmap(0LL, 0x1000uLL, 7, 34, -1, 0LL);
  if ( buf == (void *)-1LL )
    abort();
  if ( !read(0, buf, 0xFFFuLL) )
    abort();
  ((void (*)(void))buf)();
  return 0;
}