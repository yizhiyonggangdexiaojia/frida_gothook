function parseSoInfo(soinfo_addr) {
    return {
        phdr: soinfo_addr.add(0).readPointer(),
        base: soinfo_addr.add(16).readPointer(),
        size: soinfo_addr.add(24).readULong(),
        dynamic: soinfo_addr.add(32).readPointer(),
        strtab: soinfo_addr.add(56).readPointer(),
        symtab: soinfo_addr.add(64).readPointer(),
        plt_rela: soinfo_addr.add(104).readPointer(),
        plt_rela_count: soinfo_addr.add(112).readULong(),
        rela: soinfo_addr.add(120).readPointer(),
        rela_count: soinfo_addr.add(128).readULong(),
        init_array: soinfo_addr.add(152).readPointer(),
        init_array_count: soinfo_addr.add(160).readULong(),
        fini_array: soinfo_addr.add(168).readPointer(),
        fini_array_count: soinfo_addr.add(176).readULong(),
        init_func: soinfo_addr.add(184).readPointer(),
        fini_func: soinfo_addr.add(192).readPointer(),
        link_map_head: {
            l_addr: soinfo_addr.add(208),
            l_name: soinfo_addr.add(216).readPointer()
        },
        load_bias: soinfo_addr.add(248).readPointer(),

        next: function () {
            return parseSoInfo(soinfo_addr.add(40).readPointer())
        },

        // 一般都是空的
        getSoname: function () {
            return this.link_map_head.l_name.readUtf8String()
        },

        // 获取std::string的字符串内容
        // 一般都有值，可能有问题，有问题std::string，但是我还是实现了，因为爱情
        getRealpath: function () {
            const realpath_addr = soinfo_addr.add(432);
            return readStdString(realpath_addr);
        }
    };
}

// 0x18大小
function parseElf64_Rela(rela_addr) {
    return {
        r_offset: rela_addr.readULong(),
        r_info: rela_addr.add(8).readULong(),
        r_addend: rela_addr.add(16).readLong()
    };
}

// 0x18大小
function parseElf64_Sym(sym_addr) {
    return {
        st_name: sym_addr.readU32(),
        st_info: sym_addr.add(4).readU8(),
        st_other: sym_addr.add(5).readU8(),
        st_shndx: sym_addr.add(6).readU16(),
        st_value: sym_addr.add(8).readPointer(),
        st_size: sym_addr.add(16).readULong(),

        // 辅助方法：获取符号类型
        getType: function () {
            return this.st_info & 0xf; // ELF32_ST_TYPE(i) ((i)&0xf)
        },

        // 辅助方法：获取符号绑定属性
        getBind: function () {
            return this.st_info >> 4; // ELF32_ST_BIND(i) ((i)>>4)
        }
    };
}

function readStdString(str_addr) {
    // 小字符串优化情况 - 通常在23字节内的字符串直接存储在对象中
    try {
        // 长字符串情况 - 第一个8字节是指向实际字符串的指针
        const str_ptr = str_addr.readPointer();
        return str_ptr.readUtf8String();
    } catch {
        console.log(str_addr.sub(15).readUtf8String())
        return str_addr.sub(15).readUtf8String();
    }
}

function getSoInfoHead() {
    const module = Process.findModuleByName("linker64");
    const symbols = module.enumerateSymbols();
    let soInfoHead = null;
    for (let i = 0; i < symbols.length; i++) {
        let symbol = symbols[i];
        if (symbol.name.indexOf("__dl__ZL6solist") !== -1) {
            soInfoHead = symbol.address;
            break;
        }
    }
    if (!soInfoHead) {
        throw new Error("linker解析错误")
    }
    return soInfoHead.readPointer();
}

function readLinkMap(linkMapAddr) {
    // 读取link_map结构体
    const l_addr = linkMapAddr.readPointer();   // ElfW(Addr) l_addr
    const l_name_ptr = linkMapAddr.add(Process.pointerSize).readPointer();  // char* l_name
    const l_ld = linkMapAddr.add(Process.pointerSize * 2).readPointer();  // ElfW(Dyn)* l_ld
    const l_next = linkMapAddr.add(Process.pointerSize * 3).readPointer();  // struct link_map* l_next
    const l_prev = linkMapAddr.add(Process.pointerSize * 4).readPointer();  // struct link_map* l_prev

    // 读取l_name指向的字符串
    let l_name = "";
    if (!l_name_ptr.isNull()) {
        l_name = l_name_ptr.readUtf8String();
    }

    return {
        l_addr: l_addr,
        l_name: l_name,
        l_ld: l_ld,
        l_next: l_next,
        l_prev: l_prev
    };
}

function getSoInfo(so_name) {
    let soInfo = parseSoInfo(getSoInfoHead())
    while (true) {
        let realPath;
        realPath = soInfo.getSoname()
        if (realPath && realPath.indexOf(so_name) !== -1) {
            return soInfo
        }
        try {
            soInfo = soInfo.next()
        } catch (e) {
            break
        }
    }
}


function getPltAddr(so_name, funcName) {
    const soInfo = getSoInfo(so_name)
    // // so地址
    // console.log(soInfo.getRealpath());
    //
    // // init段
    // console.log(soInfo.init_array.sub(soInfo.base));
    //
    // // plt R_AARCH64_GLOB_DAT段，本身全局会用到
    // console.log(soInfo.rela.sub(soInfo.base))
    // console.log(soInfo.rela.sub(soInfo.base).add(soInfo.rela_count * 0x18))
    //
    // // plt R_AARCH64_JUMP_SLOT段，import导入会用到
    // console.log(soInfo.plt_rela.sub(soInfo.base))
    // console.log(soInfo.plt_rela.sub(soInfo.base).add(soInfo.plt_rela_count * 0x18))

    // // 字符串
    // console.log(soInfo.strtab.sub(soInfo.base))

    // // 符号信息
    // console.log(soInfo.symtab.sub(soInfo.base))

    let elf64Rela = null;
    for (let i = 0; i < soInfo.plt_rela_count; i++) {
        // console.log("elf64Rela偏移: " + soInfo.plt_rela.add(i * 0x18).sub(soInfo.base))
        const _elf64Rela = parseElf64_Rela(soInfo.plt_rela.add(i * 0x18));
        // 右移32位，得到的就是第
        const _offset = Number(BigInt(_elf64Rela.r_info) >> 32n)
        const _elf64SymAddr = soInfo.symtab.add(_offset * 0x18)
        // console.log("elf64Sym偏移: " + _elf64SymAddr.sub(soInfo.base))
        const _elf64Sym = parseElf64_Sym(_elf64SymAddr);
        const _funcName = soInfo.strtab.add(_elf64Sym.st_name).readUtf8String()
        if (_funcName === funcName) {
            elf64Rela = _elf64Rela
            break
        }
    }
    if (!elf64Rela) {
        throw new Error("找不到so")
    }
    console.log("got hook offset:", elf64Rela.r_offset.toString(16))
    return soInfo.base.add(elf64Rela.r_offset)
}

function GotHook(so_name, funcName, newFuncAddr){
    let gotAddress = getPltAddr(so_name, funcName)
    console.log("gotAddress:", gotAddress)
    // 函数替换
    Memory.protect(gotAddress, 8, "rw-")
    gotAddress.writePointer(newFuncAddr)
    console.log("gotAddress hook after", gotAddress.readPointer())
    Memory.protect(gotAddress, 8, "r--")
}

function create_pthread_create() {
    const pthread_create_addr = Module.findExportByName(null, "pthread_create")
    const pthread_create = new NativeFunction(pthread_create_addr, "int", ["pointer", "pointer", "pointer", "pointer"]);
    return new NativeCallback((parg0, parg1, parg2, parg3) => {
        const module = Process.findModuleByAddress(parg2);
        const so_name = module.name;
        const baseAddr = module.base
        console.log("pthread_create", so_name, "0x" + parg2.sub(baseAddr).toString(16), "0x" + parg3.toString(16))
        // 成功的返回值是0
        return pthread_create(parg0, parg1, parg2, parg3)
    }, "int", ["pointer", "pointer", "pointer", "pointer"])
}

var new_pthread_create = create_pthread_create()
GotHook("libhhh.so", "pthread_create", new_pthread_create)
