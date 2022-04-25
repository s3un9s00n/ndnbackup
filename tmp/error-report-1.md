### NFD

```bash
root@ubuntu:/home/lsh/Desktop/CALab-NDN-Dev/tmp/build/github_NFD# ./waf
Waf: Entering directory `/home/lsh/Desktop/CALab-NDN-Dev/tmp/build/github_NFD/build'
fatal: not a git repository (or any of the parent directories): .git
Extension 'sphinxcontrib.doxylink' not found. Some documentation may not build correctly.
[141/160] Compiling tools/nfdc/rib-module.cpp
[150/160] Compiling tools/nfdc/face-module.cpp
../tools/nfdc/rib-module.cpp: In static member function ‘static void nfd::tools::nfdc::RibModule::add(nfd::tools::nfdc::ExecuteContext&)’:
../tools/nfdc/rib-module.cpp:174:28: error: ‘class ndn::Name’ has no member named ‘find’
  174 |     iComponentEnd = prefix.find('/', iComponentStart);
      |                            ^~~~
../tools/nfdc/rib-module.cpp:179:23: error: ‘class ndn::Name’ has no member named ‘c_str’
  179 |     strcpy(pt, prefix.c_str().substr(iComponentStart, iComponentEnd-iComponentStart));
      |                       ^~~~~

Waf: Leaving directory `/home/lsh/Desktop/CALab-NDN-Dev/tmp/build/github_NFD/build'
Build failed
 -> task in 'tools-nfdc-objects' failed with exit status 1 (run with -v to display more information)
root@ubuntu:/home/lsh/Desktop/CALab-NDN-Dev/tmp/build/github_NFD# client_loop: send disconnect: Broken pipe
```