# Based on Brandon Azad's ida_kernelcache
## Requirement
- [iometa](https://github.com/Siguza/iometa)
- [jtool2](http://www.newosxbook.com/tools/jtool.html)
  
## How to use?
  
1. `iometa -n -A [kernelcache] > /tmp/kernel.txt`
2. `jtool2 --analyze [kernelcache]; mv [kernelcache companion file] /tmp/kernel_jtool2.txt`
3. IDA에서 script -> `ida_kernelcache.py`를 로딩
4. python prompt에 `kc.kernelcache_process()` 실행
