from typing import Union

from gmpy2 import mpz, powmod


class ChosenCiphertextAttack:
    __ParameterTypes = Union[int, bytes]
    __ReturnTypes = Union[int, bytes]

    def __init__(self, e: __ParameterTypes, N: __ParameterTypes):
        self.e = e
        self.n = N

    def get_self_Ciphertext(self, C: __ParameterTypes, _const_base_me_param: int = 2) -> __ReturnTypes:
        """
        Метод формирует собсвенный CipherText для работы алгоритма CCA
        :param C:
        :param _const_base_me_param:
        :return:
        """
        assert isinstance(C, tuple(self.__ParameterTypes))
        if isinstance(C, bytes):
            C = int.from_bytes(C, 'big')

        Ca = powmod(mpz(_const_base_me_param), mpz(self.e), mpz(self.N))
        Cb = Ca * C
        return Cb

    def chosen_cipher_attack(self, recvC: __ParameterTypes, _const_base_me_param: int = 2) -> __ReturnTypes:
        """
        CCA ( chosen cipher attack)    -    используется, когда у нас есть возможность отправлять сообщение на
                   или                      подпись ( в случае удостоверящего центра ) или
            алгоритм ослепления             расшифровку ( в случае использования обычного алгоритма RSA )


        Принцип работы -    Для того, чтобы расшифровать C нужно подмешать в него выбранное случайное число и
                            отправить на расшифровку. По теории Эйлера мы получим сообщение, которые останется только
                            поделить на выбранное число и БАААААМ!!!!!. Мы получаем расшифрованное сообщение

        """
        assert isinstance(recvC, tuple(self.__ParameterTypes))
        if isinstance(recvC, bytes):
            recvC = int.from_bytes(recvC, 'big')

        return recvC // _const_base_me_param
