#!/usr/bin/env python
# Created by @v3x4r

import os
import string
import random
import server
import client
import subprocess
import threading

from selenium import webdriver
from time import sleep

DIRECT = './result'  # Папка, куда все будет генерироваться
CAT_FILE = './cat.jpg'  # Картинка с котиком
ANS_DIR = './result/answers'
PCAP_DIR = './result/pcap'
ANSWER_SIZE = 8  # Длина кода-ответа
PASSWD_SIZE = 8
AMOUNT = 3  # Количество вариантов
INTERFACE = 'wlp1s0'
EXE_PATH = './chromedriver'
UPLOAD_FILES_SITE = 'https://filecloud.me/'


class Context:
    tshark_process = None


context = Context()  # Костыль, так надо


def tshark_callback(interface, name):
    context.tshark_process = subprocess.Popen([
        'tshark',
        '-i', interface,
        '-w', name],
        stdout=subprocess.PIPE)


def get_text_filename_and_answer(size=ANSWER_SIZE,
                                 chars=string.ascii_letters + string.digits,
                                 number=int()):
    """
    Генерирует текстовые файлы с ответами для студентов

    :param size: int
    :param chars: буквы и цифры
    :param number: int
    :return: название файла и ответ для студента
    """
    file_name = '{dir}/{number}.txt'.format(dir=DIRECT, number=number)
    text_file = open(file_name, 'w')
    answer = 'Ваш код: {}'.format(
        ''.join(random.choice(chars) for _ in range(size)))
    text_file.write(answer)

    return file_name, answer


def get_passwd_list_and_create_archive():
    """
    Генерируются запароленные архивы.

    :return: Список с паролями от архивов
    """
    password_list = list()
    check_list = list()

    for count in range(1, AMOUNT + 1):
        text_file_name, text_code = get_text_filename_and_answer(number=count)
        check_list.append([count, text_code])

        passwd = ''.join(
            random.choice(string.ascii_letters + string.digits) for _ in
            range(PASSWD_SIZE))

        password_list.append(passwd)
        os.system(
            '7z a {dir}/{num}.7z {file1} {file2} -p{passwd}'.format(dir=DIRECT,
                                                                    num=count,
                                                                    file1=text_file_name,
                                                                    file2=CAT_FILE,
                                                                    passwd=passwd))

    checker = open('{}/check.txt'.format(ANS_DIR), 'w+')
    for item in check_list:
        checker.write('{}\n'.format(item))

    return password_list


def generate_key_log(down_file, num):
    options = webdriver.ChromeOptions()
    options.add_argument(
        '--ssl-key-log-file={dir}/{number}.log'.format(dir=DIRECT,
                                                       number=num))
    browser = webdriver.Chrome(executable_path=EXE_PATH,
                               options=options)
    browser.get(down_file)
    browser.find_element_by_link_text('Скачать').click()
    sleep(4)
    browser.close()


def get_download_file_list(num):
    options = webdriver.ChromeOptions()
    options.add_argument(
        '--ssl-key-log-file={dir}/{number}.log'.format(dir=DIRECT,
                                                       number=num))
    browser = webdriver.Chrome(executable_path=EXE_PATH,
                               options=options)
    print('Chrome is init')

    # for num in range(1, AMOUNT):
    browser.get(UPLOAD_FILES_SITE)
    browser.find_element_by_id('fileupload').send_keys(
        '{dir}/{num}.7z'.format(dir=DIRECT, num=num))
    sleep(2)
    browser.find_element_by_link_text('Отправить').click()
    sleep(3)
    # file_name = browser.find_element_by_id('all_files_download_link')
    # download_file_list.append(file_name.text)
    # sleep(4)
    print('Загружен {num} файл!'.format(num=num))

    browser.close()


def concat_pcap_files():
    """
    Склеивает pcap файлы
    """
    for number in range(1, AMOUNT + 1):
        os.system('cat {pcap}/{num}\(1\).pcapng '
                  '{pcap}/{num}\(2\).pcapng > '
                  '{answers}/{num}.pcapng'.format(pcap=PCAP_DIR,
                                                  answers=ANS_DIR,
                                                  num=number))


def main():
    passwd_list = get_passwd_list_and_create_archive()  # Создаем архивы и получаем список паролей от них

    for round in range(1, AMOUNT + 1):
        tshark_thread1 = threading.Thread(
            target=tshark_callback,
            args=(INTERFACE, '{dir}/{num}(1).pcapng'.format(
                dir=PCAP_DIR,
                num=round),))

        generate_traffic_thread = threading.Thread(
            target=get_download_file_list,
            args=(round,))  # Загружаем эти архивы на файлообменник

        tshark_thread1.start()  # Начинаем генерировать первый трафик
        sleep(2)
        generate_traffic_thread.start()  # Генерируем ssl лог

        sleep(10)
        context.tshark_process.terminate()

        print("***Первый трафик готов***")
        #######################################################################

        tshark_thread2 = threading.Thread(target=tshark_callback,
                                          args=(
                                              'lo',
                                              '{dir}/{num}(2).pcapng'.format(
                                                  dir=PCAP_DIR,
                                                  num=round),))
        server_thread = threading.Thread(target=server.start_server,
                                         args=('{dir}/{num}.log'.format(
                                             dir=DIRECT,
                                             num=round),
                                               passwd_list[round],
                                               60000 + round),
                                         daemon=True)
        client_thread = threading.Thread(target=client.start_client,
                                         args=(60000 + round,))

        tshark_thread2.start()  # Начинаем генерировать второй трафик
        sleep(3)
        server_thread.start()  # Запускаем сервер
        sleep(1)
        client_thread.start()  # Запускаем клиент
        sleep(3)

        context.tshark_process.terminate()

        print('***Второй трафик готов***')

    concat_pcap_files()


main()
