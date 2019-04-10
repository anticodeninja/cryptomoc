Практикум "Прикладная криптография"
===================================

Репозиторий содержит набор практический заданий по курсу "Прикладная криптография", каждое из которых может включать в себя:

* Небольшое, но емкое описание.
* Генератор вариантов для заданий (студентов может быть много, а преподаватель как правило один).
* Автоматический тестер для сделанных заданий (примечение выше корректно и здесь).


Быстрый старт
-------------

    # Устанавливаем cryptomoc
    git clone https://github.com/anticodeninja/cryptomoc.git
    pip install -e cryptomoc

    # Создаем окружение
    mkdir cryptomoc-env
    cd cryptomoc-env
    cryptomoc core init

    # Заполняем файл со списком студентов
    # 1 - ФИО, 2 - email, 3 - keybase login, 4 - keybase fingerprint
    # keybase login and fingerprint получаются из первой лабораторной,
    # сейчас можно оставить по умолчанию
    vi students.csv

    # Смотрим список доступных заданий
    cryptomoc core modules

    # Генерируем задание для первой лабораторной работы
    cryptomoc keybase gen
    ls keybase

    # Проверяем код присланный студентом
    cryptomoc keybase check BLABLA

Для каждой практики можно получить помощь по самой практике и её набору функций воспользовавшись встроенной справкой:

    cryptomoc keybase -h
    cryptomoc keybase gen -h


Ошибки и доработка
------------------

Несмотря на то, что данный инструментарий был дважды опробован при проведении практических занятий (второй раз на догоняющих студентах), очень вероятно, что еще не все ошибки обнаружены и не все функции работают так, как от них ожидается.
Поэтому приветствуется обратная связь в виде баг-репортов или PR их исправляющих.