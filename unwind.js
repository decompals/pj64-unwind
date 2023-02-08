const elf_path = "path/to/file.elf";
console.clear();

var mod = require('unwind.dll');
console.log("Loading elf file...");
console.log(mod.unwind(elf_path));
