from idea import IDEA

def main():
    # Pengguna memilih opsi enkripsi atau dekripsi
    tanya = input('\nEnkripsi atau Dekripsi? (e/d)\t\t')

    # Pilih enkripsi
    if tanya == 'e':

        # Mengatur kunci enkripsi
        tanya = input('\nIngin memakai key bawaan? (y/n)\t\t')
        if tanya == 'y':
            key = 0x6E3272357538782F413F4428472B4B62
            print(f"\nKey:\t\t{hex(key)}\n")
        elif tanya == 'n':
            key = input("Masukan key (hex):\t\t")
            print("\n")
            key = int(key, 16)

        my_IDEA = IDEA(key)

        # Masukan plainteks dan transformasi
        plain = input("Masukan plainteks (ASCII):\t\t")
        plain = int.from_bytes(plain.encode("ASCII"), 'big')
        size = plain.bit_length()

        sub_plain = []
        sub_enc = []

        # Enkripsi
        x = size // 64
        if size % 64 != 0:
            x += 1
            size += 64 - size % 64
        for i in range(x):
            shift = size - (i+1) * 64
            sub_plain.append((plain >> shift) & 0xFFFFFFFFFFFFFFFF)
            enkripsi = my_IDEA.enkrip(sub_plain[i])
            sub_enc.append(enkripsi)
            enkripsi = 0
        for i in range(x):
            sub_enc[i] = sub_enc[i] << (x - (i + 1)) * 64
            enkripsi = enkripsi | sub_enc[i]

        print(f"\nEnkripsi:\thex: {hex(enkripsi)}\n")

        tanya = input("Ingin mengecek dekripsi? (y/n)\t\t")

        # Dekripsi
        if tanya == 'y':
            sub_dec = []
            size = enkripsi.bit_length()
            if size % 64 != 0:
                x = size // 64 + 1
                size += 64 - size % 64
            else:
                x = size // 64
            dekripsi = 0
            for i in range(x):
                shift = size - (i+1) * 64
                k = (enkripsi >> shift) & 0xFFFFFFFFFFFFFFFF
                sub_dec.append(my_IDEA.dekrip(k))
            for i in range(x):
                    sub_dec[i] = sub_dec[i] << (x - (i + 1)) * 64
                    dekripsi = dekripsi | sub_dec[i]
                
            print(f"\nDekripsi:\thex: {hex(dekripsi)}")
            print(f"\t\tuni: {dekripsi.to_bytes(64, 'big').decode('ASCII')}\n")
        else:
            pass

    # Pilih dekripsi
    elif tanya == 'd':

        # Mengatur kunci
        tanya = input(('\nIngin memakai key bawaan? (y/n)\t\t'))
        if tanya == 'y':
            key = 0x6E3272357538782F413F4428472B4B62
            print(f"\nKey:\t\t{hex(key)}\n")
        elif tanya == 'n':
            key = input("Masukan key (hex):\t\t")
            print("\n")
            key = int(key, 16)

        my_IDEA = IDEA(key)

        # Masukan cipherteks dan transformasi
        enkripsi = input("Masukan cipherteks (hex):\t")
        enkripsi = int(enkripsi, 16)
        sub_dec = []
        size = enkripsi.bit_length()

        # Dekripsi
        if size % 64 != 0:
            x = size // 64 + 1
            size += 64 - size % 64
        else:
            x = size // 64
        dekripsi = 0
        for i in range(x):
            shift = size - (i+1) * 64
            k = (enkripsi >> shift) & 0xFFFFFFFFFFFFFFFF
            sub_dec.append(my_IDEA.dekrip(k))
        for i in range(x):
                sub_dec[i] = sub_dec[i] << (x - (i + 1)) * 64
                dekripsi = dekripsi | sub_dec[i]

        print(f"\nDekripsi:\thex: {hex(dekripsi)}")
        print(f"\t\tuni: {dekripsi.to_bytes(64, 'big').decode('ASCII')}\n")

    # Tidak sesuai dengan opsi pilihan
    else:
        pass 


if __name__ == '__main__':
    main()