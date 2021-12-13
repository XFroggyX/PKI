"""
Кодироваие файла публичным ключом из сертефиката
"""

import chilkat
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP


class PKI:
    def __init__(self):
        self.stores = ["MY", "Root", "Trust", "CA", "UserDS"]
        self.cert_stores = chilkat.CkCertStore()

    def get_list_stores(self) -> list:
        return self.stores

    def get_list_certs_store(self, store_name: str) -> list:
        """Список сертеикатов store_name хранилиа"""
        self.cert_stores.OpenWindowsStore("CurrentUser", store_name, True)
        return [self.cert_stores.GetCertificate(i) for i in range(self.cert_stores.get_NumCertificates())]

    def print_list_certs_store(self, store_name: str) -> None:
        list_certs = self.get_list_certs_store(store_name)
        for cert in list_certs:
            print(f"#{cert.subjectDN()}\nHASH = {cert.sha1Thumbprint()}\n")

    def gen_pem(self, store_name: str, cert_cn=None, public_file="public.pem"):
        if cert_cn is None:
            cert_cn = input("Введите comand name > ")

        self.get_list_certs_store(store_name)
        select_cert = self.cert_stores.FindCertBySubjectCN(cert_cn)

        public_key = select_cert.ExportPublicKey()
        ret_str = public_key.getPem(True)

        with open(public_file, "wb") as file:
            file.write(ret_str.encode())

    @staticmethod
    def encode_file(name_text_file: str, name_pem_file: str, encode_file: str) -> None:
        with open(name_text_file, "r") as file:
            text = file.read()

        with open(name_pem_file, "r") as file:
            pem = file.read()

        key = RSA.import_key(pem)
        key = PKCS1_OAEP.new(key)

        encode_ = key.encrypt(text.encode())
        with open(encode_file, "wb") as file:
            file.write(encode_)


if __name__ == '__main__':
    pki = PKI()
    print("Список хранилищ:", ", ".join(pki.get_list_stores()))
    name_pki = input("Выберите хранилище > ")
    print("Список сертефикатов в хранилище: ")
    pki.print_list_certs_store(name_pki)
    pki.gen_pem(name_pki)
    pki.encode_file("text", "public.pem", "new.bin")
