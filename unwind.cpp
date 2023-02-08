#include <cstdint>
#include <memory>
#include <cstdio>
#include <format>
#include <map>
#include <algorithm>
#include <optional>
#include "elfio/elfio.hpp"
#include "duktape.h"

ELFIO::section* get_symtab(const ELFIO::elfio& elf_file) {    
    for (const auto& section : elf_file.sections) {
        if (section->get_type() == ELFIO::SHT_SYMTAB) {
            return section.get();
        }
    }
    return nullptr;
}

constexpr uint32_t thread_offset_next = 0x0;
constexpr uint32_t thread_offset_id = 0x14;
constexpr uint32_t thread_offset_pri = 0x4;
constexpr uint32_t thread_offset_pc = 0x20 + 0xFC;
constexpr uint32_t thread_offset_ra = 0x20 + 0xE4;
constexpr uint32_t thread_offset_sp = 0x20 + 0xD4;

struct Func {
    uint32_t vram;
    std::string name;
    size_t size;
    Func(uint32_t vram_, std::string&& name_, size_t size_) :
        vram(vram_), name(std::move(name_)), size(size_) {}
};

struct ElfData {
    uint32_t __osRunningThread;
    uint32_t __osRunQueue;
    uint32_t __osThreadTail;
    std::vector<Func> functions;
    bool good() {
        return __osRunningThread != 0 && __osRunQueue != 0 && __osThreadTail != 0 && functions.size() > 0;
    }
};

ElfData get_functions(const ELFIO::elfio& elf_file, ELFIO::section* symtab) {
    ELFIO::symbol_section_accessor symbols{elf_file, symtab};
    ElfData ret{};

    for (size_t sym_index = 0; sym_index < symbols.get_symbols_num(); sym_index++) {
        std::string   name;
        ELFIO::Elf64_Addr    value;
        ELFIO::Elf_Xword     size;
        unsigned char bind;
        unsigned char type;
        ELFIO::Elf_Half      section_index;
        unsigned char other;

        // Read symbol properties
        symbols.get_symbol(sym_index, name, value, size, bind, type,
            section_index, other);

        // Check if this symbol is a function or has no type (like a regular glabel would)
        // Symbols with no type have a dummy entry created so that their symbol can be looked up for function calls
        if (type == ELFIO::STT_FUNC && !name.starts_with("dead_")) {
            ret.functions.emplace_back(value, std::move(name), size);
        }
        else {
            if (name == "__osRunningThread") {
                ret.__osRunningThread = value;
            }
            else if (name == "__osRunQueue") {
                ret.__osRunQueue = value;
            }
            else if (name == "__osThreadTail") {
                ret.__osThreadTail = value;
            }
        }
    }
    std::sort(ret.functions.begin(), ret.functions.end(),
        [](const Func& a, const Func& b){
            return a.vram < b.vram;
        }
    );
    return ret;
}

void* get_rdram(duk_context* ctx) {
    duk_get_global_string(ctx, "mem");
    duk_get_prop_string(ctx, -1, "ptr");
    return duk_get_pointer(ctx, -1);
}

std::optional<uint32_t> read_u32_tlb(duk_context* ctx, uint32_t addr) {
    duk_push_string(ctx, ("mem.u32[" + std::to_string(addr) + "]").c_str());
    if (!duk_peval(ctx)) {
        return duk_get_number(ctx, -1);
    } else {
        return std::nullopt;
    }
}

uint32_t get_cpu_reg(duk_context* ctx, const std::string& name) {
    duk_push_string(ctx, ("cpu.gpr." + name).c_str());
    if (!duk_peval(ctx)) {
        return duk_get_number(ctx, -1);
    } else {
        duk_push_error_object(ctx, -1, "Invalid register name", name.c_str());
        return 0;
    }
}

uint32_t get_cpu_pc(duk_context* ctx) {
    duk_push_string(ctx, "cpu.pc");
    if (!duk_peval(ctx)) {
        return duk_get_number(ctx, -1);
    } else {
        duk_push_error_object(ctx, -1, "Failed to get program counter");
        return 0;
    }
}

uint32_t virtual_to_physical(uint32_t addr) {
    return addr - 0x80000000;
}

template <typename T>
T read_mem(const void* rdram, size_t addr) {
    return *reinterpret_cast<const T*>(reinterpret_cast<uintptr_t>(rdram) + virtual_to_physical(addr));
}

constexpr uint32_t jal_mask   = 0xFC000000;
constexpr uint32_t jal_value  = 0x0C000000;
constexpr uint32_t jalr_mask  = 0xFC1F07FF;
constexpr uint32_t jalr_value = 0x00000009;

// Gets the function that contains a given address, or nullptr if none was found
const Func* get_func(const ElfData& elf_data, uint32_t addr) {
    auto func_it = std::upper_bound(elf_data.functions.begin(), elf_data.functions.end(), addr,
        [](uint32_t cur_pc, const Func& func) {
            return cur_pc < func.vram;
        }
    );
    if (func_it != elf_data.functions.begin()) {
        return &*(func_it - 1);
    } else {
        return (const Func*)nullptr;
    }
}

// Checks if the given potential return address is correct
bool is_next_function(duk_context* ctx, uint32_t test_ra, const Func* cur_func, uint32_t cur_pc) {
    std::optional<uint32_t> call_instr_opt = read_u32_tlb(ctx, test_ra - 2 * sizeof(uint32_t));
    if (!call_instr_opt.has_value()) {
        return false;
    }
    
    uint32_t call_instr = call_instr_opt.value();
    bool is_jal = (call_instr & jal_mask) == jal_value;
    bool is_jalr = (call_instr & jalr_mask) == jalr_value;

    // If we find a jal, check that it's pointing to this function
    if (is_jal) {
        uint32_t target_addr = (call_instr & 0x3FFFFFFu) << 2;
        target_addr |= cur_pc & 0xF0000000;
        return cur_func ? (target_addr == cur_func->vram) : true;
    }
    // We can't check if a jalr points to the current function, so just assume it does.
    else if (is_jalr) {
        return true;
    }

    return false;
}

std::string get_stacktrace(duk_context* ctx, const void* rdram, const ElfData& elf_data, uint32_t pc, uint32_t sp, uint32_t ra) {
    uint32_t last_sp = sp + 256 * sizeof(uint32_t); // This should be a reasonable max stack size
    std::string ret = "";
    const Func* cur_func;
    
    cur_func = get_func(elf_data, pc);
    ret += std::format("    {}: 0x{:08X}\n", cur_func ? cur_func->name : "unknown", pc);

    // If the return address points to another function, then it's valid.
    // Otherwise, control has returned from a function called by the current one and the $ra register
    // hasn't been reloaded from the stack yet.
    const Func* ra_func = get_func(elf_data, ra);
    if (ra_func != cur_func && is_next_function(ctx, ra, cur_func, pc)) {
        cur_func = ra_func;
        pc = ra;
        ret += std::format("    {}: 0x{:08X}\n", cur_func ? cur_func->name : "unknown", pc);
    }

    while (sp < last_sp) {
        uint32_t stack_val = read_mem<uint32_t>(rdram, sp);
        std::optional<uint32_t> pointed_val_opt = read_u32_tlb(ctx, stack_val - sizeof(uint32_t) * 2);
        if (is_next_function(ctx, stack_val, cur_func, pc)) {
            pc = stack_val;
            cur_func = get_func(elf_data, pc);
            ret += std::format("    {}: 0x{:08X} @ 0x{:08X} (0x{:08X})\n", cur_func ? cur_func->name : "unknown", pc, sp, pointed_val_opt.value_or(-1));
            last_sp = sp + 256 * sizeof(uint32_t);
        }
        sp += sizeof(uint32_t);
    }
    return ret;
}

std::string read_thread(duk_context* ctx, const void* rdram, const ElfData& elf_data, uint32_t thread_addr, uint32_t pc, uint32_t ra, uint32_t sp) {
	uint32_t id = read_mem<uint32_t>(rdram, thread_addr + thread_offset_id);
	uint32_t pri = read_mem<uint32_t>(rdram, thread_addr + thread_offset_pri);

	return std::format(
        " id: {} @ 0x{:08X}\n"
	    "  pri: {}\n"
	    "  pc: 0x{:08X}\n"
	    "  sp: 0x{:08X}\n"
	    "  ra: 0x{:08X}\n"
        "  stacktrace:\n{}",
        id, thread_addr, pri, pc, sp, ra, get_stacktrace(ctx, rdram, elf_data, pc, sp, ra)
    );
}

static duk_ret_t unwind(duk_context* ctx) {
    const char* path = duk_get_string(ctx, -1);
    void* rdram = get_rdram(ctx);
    if (!path) {
        duk_push_string(ctx, "Bad argument type");
        return 1;
    }

    ELFIO::elfio elf_file;
    if (!elf_file.load(path)) {
        duk_push_string(ctx, "Failed to open elf file");
        return 1;
    }
    if (elf_file.get_class() != ELFIO::ELFCLASS32) {
        duk_push_string(ctx, "Incorrect elf class");
        return 1;
    }
    if (elf_file.get_encoding() != ELFIO::ELFDATA2MSB) {
        duk_push_string(ctx, "Incorrect elf endianness");
        return 1;
    }

    ELFIO::section* symtab = get_symtab(elf_file);
    if (symtab == nullptr) {
        duk_push_string(ctx, "Failed to find symtab in elf file");
        return 1;
    }

    ElfData elf_data = get_functions(elf_file, symtab);
    if (!elf_data.good()) {
        duk_push_string(ctx, "Elf file missing some necessary symbols");
        return 1;
    }

    std::string ret = "Running Thread:\n";
    ret += read_thread(ctx, rdram, elf_data, read_mem<uint32_t>(rdram, elf_data.__osRunningThread), get_cpu_pc(ctx), get_cpu_reg(ctx, "ra"), get_cpu_reg(ctx, "sp"));
    ret += "Queued Running Threads:\n";

    uint32_t cur_thread = read_mem<uint32_t>(rdram, elf_data.__osRunQueue);

    while (cur_thread != 0 && cur_thread != elf_data.__osThreadTail) {
        uint32_t pc = read_mem<uint32_t>(rdram, cur_thread + thread_offset_pc);
        uint32_t ra = read_mem<uint32_t>(rdram, cur_thread + thread_offset_ra);
        uint32_t sp = read_mem<uint32_t>(rdram, cur_thread + thread_offset_sp);
        ret += read_thread(ctx, rdram, elf_data, cur_thread, pc, ra, sp);
        cur_thread = read_mem<uint32_t>(rdram, cur_thread + thread_offset_next);
    }

    duk_push_string(ctx, ret.c_str());
    return 1;
}

static const duk_function_list_entry my_module_funcs[] = {
    { "unwind", unwind, 1 /*nargs*/ },
    { NULL, NULL, 0 }
};

static const duk_number_list_entry my_module_consts[] = {
    { NULL, 0.0 }
};

// duktape module entrypoint
extern "C" __declspec(dllexport) duk_ret_t dukopen_unwind(duk_context* ctx) {
    duk_push_object(ctx);
    duk_put_function_list(ctx, -1, my_module_funcs);
    duk_put_number_list(ctx, -1, my_module_consts);

    return 1;
}
