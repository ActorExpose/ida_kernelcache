# Made by aSiagaming

import ida_bytes
import ida_name
import ida_funcs
import idc
import idautils
import idaapi
import ida_struct
import os

# Thanks to @bazad's ida_kernelcache
import ida_utilities as idau

kernelcache_path = "/tmp/kernel_jtool2.txt"
iometa_path = "/tmp/kernel.txt"
classMap = {}

def construct_class(name):
	sid = idc.add_struc(-1, name, 0)
	idc.add_struc_member(sid, "IOUserClient", 0, idc.FF_DATA, -1, 0x1000)
	idc.SetType(idc.get_member_id(sid, 0), "IOUserClient IOUserClient");
	idc.add_struc_member(sid, "clientData", -1, idc.FF_DATA, -1, 0x1000)
	classMap[name] = sid

# jtool2 --analyze [kernelcache]
def jtool2_information():
	print("[-] Other method information construction")
	fd = open(kernelcache_path)
	data = fd.readlines()
	fd.close()	

	for line in data:
		t = line[:-1].strip()
		addr = int(t.split("|")[0], 0)
		sym = t.split("|")[1]

		segName = idc.get_segm_name(addr)
		if segName != "__TEXT_EXEC:__text" or "." in sym:
			if "__DATA" in segName:
				idaapi.set_name(addr, sym, idaapi.SN_FORCE)
			continue

		if not idau.is_function_start(addr):
			print("[jtool2] Current '{}'' - [{}] is not defined as function".format(sym, hex(addr)))
			if not idau.force_function(addr):
				print("[jtool2] Can't convert '{}' - [{}] to function".format(sym, hex(addr)))
				continue

		curSym = idc.get_func_name(addr)
		if "sub_" in curSym:
			idaapi.set_name(addr, sym, idaapi.SN_FORCE)

	print("[-] Done")

def name_resolve(current, tu):
	pass

# iometa -n -A [kernelcache] > /tmp/kernel.txt
def iometa_information():
	print("[-] UserClient Method construction")
	fd = open(iometa_path)
	data = fd.readlines()
	fd.close()

	# Current
	className = ""

	for line in data:
		t = line[:-1].strip()
		if "vtab" in t and "meta" in t:
			className = t.split(" ")[5]
			#print(className)
			continue

		#offset = int(t.split(" ")[0])
		addr = int(t.split(" ")[1][5:], 0)
		sym = idc.get_func_name(addr)
		name = t.split(" ")[4].split("(")[0]

		if not idau.is_function_start(addr):
			print("[iometa] Current '{}'' - [{}] is not defined as function".format(name, hex(addr)))
			if not idau.force_function(addr):
				print("[iometa] Can't convert '{}' - [{}] to function".format(name, hex(addr)))

		if "sub_" in sym:
			idaapi.set_name(addr, name, idaapi.SN_FORCE)

		if "externalMethod" in name:
			sid = ida_struct.get_struc_id(className)

			if sid == 0xffffffffffffffff and className != "IOUserClient":
				print("[iometa] can't resolve class {}, create one".format(className))
				construct_class(className)

			tu = ('\x0c0=\tIOReturn\x07\xffA\n=\rIOUserClient=\tuint32_t\n=\x1aIOExternalMethodArguments\n=\x19IOExternalMethodDispatch\n=\tOSObject\n\x01', '\x05this\tselector\narguments\tdispatch\x07target\nreference')
			if not idc.apply_type(addr, tu):
				print("[iometa] externalMethod type propagation failure '{}' - [{}]".format(name, hex(addr)))

	print("[-] Done")

"""
## IOUserClient::externalMethod

// Type Defs
typedef uint64_t io_user_reference_t;
Args -> (uint32_t selector, struct IOExternalMethodArguments *arguments, struct IOExternalMethodDispatch *dispatch, OSObject *target, void *reference)

struct IOExternalMethodDispatch {
    void * function;
    uint32_t               checkScalarInputCount;
    uint32_t               checkStructureInputSize;
    uint32_t               checkScalarOutputCount;
    uint32_t               checkStructureOutputSize;
};

struct IOExternalMethodArguments {
    uint32_t            version;
    uint32_t            selector;

    mach_port_t           asyncWakePort;
    uint32_t * asyncReference;
    uint32_t              asyncReferenceCount;

    const uint64_t *    scalarInput;
    uint32_t            scalarInputCount;

    const void *        structureInput;
    uint32_t            structureInputSize;

    void * structureInputDescriptor;

    uint64_t *          scalarOutput;
    uint32_t            scalarOutputCount;

    void *              structureOutput;
    uint32_t            structureOutputSize;

    void * structureOutputDescriptor;
    uint32_t             structureOutputDescriptorSize;
    uint32_t            __reservedA;
    void **         structureVariableOutputData;
    uint32_t            __reserved[30];
};

"""

# externalMethod struct
# Maybe don't need it in > IDA 7.5?
def struct_init():
	IOExternalMethodDispatch = idc.add_struc(-1, "IOExternalMethodDispatch", 0)
	idc.add_struc_member(IOExternalMethodDispatch, "function", -1, idc.FF_QWORD, -1, 8)
	idc.add_struc_member(IOExternalMethodDispatch, "checkScalarInputCount", -1, idc.FF_DWORD, -1, 4)
	idc.add_struc_member(IOExternalMethodDispatch, "checkStructureInputSize", -1, idc.FF_DWORD, -1, 4)
	idc.add_struc_member(IOExternalMethodDispatch, "checkScalarOutputCount", -1, idc.FF_DWORD, -1, 4)
	idc.add_struc_member(IOExternalMethodDispatch, "checkStructureOutputSize", -1, idc.FF_DWORD, -1, 4)

	IOExternalMethodArguments = idc.add_struc(-1, "IOExternalMethodArguments", 0)
	idc.add_struc_member(IOExternalMethodArguments, "version", -1, idc.FF_DWORD, -1, 4)
	idc.add_struc_member(IOExternalMethodArguments, "selector", -1, idc.FF_DWORD, -1, 4)
	idc.add_struc_member(IOExternalMethodArguments, "asyncWakePort", -1, idc.FF_DWORD, -1, 4)
	idc.add_struc_member(IOExternalMethodArguments, "asyncReference", -1, idc.FF_QWORD, -1, 8)
	idc.add_struc_member(IOExternalMethodArguments, "asyncReferenceCount", -1, idc.FF_DWORD, -1, 4)
	
	idc.add_struc_member(IOExternalMethodArguments, "scalarInput", -1, idc.FF_QWORD, -1, 8)
	idc.add_struc_member(IOExternalMethodArguments, "scalarInputCount", -1, idc.FF_DWORD, -1, 4)
	idc.add_struc_member(IOExternalMethodArguments, "structureInput", -1, idc.FF_QWORD, -1, 8)
	idc.add_struc_member(IOExternalMethodArguments, "structureInputSize", -1, idc.FF_DWORD, -1, 4)
	idc.add_struc_member(IOExternalMethodArguments, "structureInputDescriptor", -1, idc.FF_QWORD, -1, 8)

	idc.add_struc_member(IOExternalMethodArguments, "scalarOutput", -1, idc.FF_QWORD, -1, 8)
	idc.add_struc_member(IOExternalMethodArguments, "scalarOutputCount", -1, idc.FF_DWORD, -1, 4)
	idc.add_struc_member(IOExternalMethodArguments, "structureOutput", -1, idc.FF_QWORD, -1, 8)
	idc.add_struc_member(IOExternalMethodArguments, "structureOutputSize", -1, idc.FF_DWORD, -1, 4)
	idc.add_struc_member(IOExternalMethodArguments, "structureOutputDescriptor", -1, idc.FF_QWORD, -1, 8)

	idc.add_struc_member(IOExternalMethodArguments, "structureOutputDescriptorSize", -1, idc.FF_DWORD, -1, 4)
	idc.add_struc_member(IOExternalMethodArguments, "__reservedA", -1, idc.FF_DWORD, -1, 4)
	idc.add_struc_member(IOExternalMethodArguments, "structureVariableOutputData", -1, idc.FF_QWORD, -1, 8)
	idc.add_struc_member(IOExternalMethodArguments, "__reserved", -1, idc.DWORD, -1, 30)


def analyze(iometa, jtool2):
	kernelcache_path = iometa
	iometa_path = jtool2

	print("[+] kernelcache UserClient info analyze")
	iometa_information()
	jtool2_information()
	print("[+] All Done")	

if __name__ == "__main__":
	print("[+] kernelcache UserClient info analyze")
	iometa_information()
	jtool2_information()
	print("[+] All Done")










