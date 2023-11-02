from capstone import Cs, CS_ARCH_X86, CS_MODE_64


def main():
    file = open("x86_code", "w")
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    with open("app.exe", "rb") as file_app:
        while True:
            byte = file_app.read(1)
            if not byte:
                break
            for i in md.disasm(byte, 0x1000):
                print(f"0x{i.address:x}:\t{i.mnemonic} {i.op_str}")
                file.write(f"{i.mnemonic} {i.op_str}\n")


if __name__ == '__main__':
    main()
