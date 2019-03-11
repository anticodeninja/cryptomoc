#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Applied Cryptography Practicum"""

import argparse
import importlib
import inspect
import os

HERE = os.path.abspath(os.path.dirname(__file__))


class LazySubParser(argparse.ArgumentParser):
    def __init__(self, *args, **kwargs):
        self.__module = kwargs.pop('module', None)
        self.__exports = kwargs.pop('exports', None)
        kwargs['formatter_class'] = argparse.RawDescriptionHelpFormatter
        super().__init__(*args, **kwargs)

    def parse_known_args(self, args=None, namespace=None):
        module = importlib.import_module(self.__module)
        self.description = module.__doc__

        subparsers = self.add_subparsers(dest='command',
                                         title='commands',
                                         parser_class=argparse.ArgumentParser)
        subparsers.required = True

        for method_name, method in inspect.getmembers(module):
            if not inspect.isfunction(method) or method_name.startswith('_'):
                continue

            command_help = None
            args_help = dict()
            if method.__doc__ is not None:
                doc = method.__doc__.splitlines()
                command_help = doc[0]
                for row in doc[1:]:
                    row = row.strip().split(' - ')
                    if len(row) == 2:
                        args_help[row[0]] = row[1]
            method_arg_parser = subparsers.add_parser(method_name,
                                                      description=command_help)

            for arg_name, arg in inspect.signature(method).parameters.items():
                default = arg.default if arg.default != arg.empty else None
                method_arg_parser.add_argument(
                    arg_name,
                    help=args_help.get(arg_name, None),
                    nargs='?' if default is not None else None,
                    default=default)

            self.__exports[method_name] = method

        return super().parse_known_args(args, namespace)


def main():
    parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.description = 'Практический практикум по курсу "Прикладная криптография"'

    subparsers = parser.add_subparsers(dest='module',
                                       title='modules',
                                       parser_class=LazySubParser)
    subparsers.required = True

    exports = dict()
    for module_name in os.listdir(HERE):
        if not os.path.exists(os.path.join(HERE, module_name, '__init__.py')):
            continue
        subparsers.add_parser(module_name,
                              exports=exports,
                              module='{}.{}'.format(__name__, module_name))

    args = parser.parse_args()
    params = {k: v for k, v in args.__dict__.items()
              if k not in ['module', 'command']}
    exports[args.command](**params)
