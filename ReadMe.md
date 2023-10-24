Different ways of hiding Windows API imports

# Dynamic PEB import # 
  This will still be caught when debugging. But hides it when statically analysing. It walks the PEB to get the base address of an already imported DLL it then finds the address of a desired exported function which can concequently be run. Hiding it from imports.
    [The best blog on this topic](https://blog.christophetd.fr/hiding-windows-api-imports-with-a-customer-loader/) <br>
    [Information on the PE export table](https://ferreirasc.github.io/PE-Export-Address-Table/)
    
