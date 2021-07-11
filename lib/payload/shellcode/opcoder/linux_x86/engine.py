#!/usr/bin/env python
# -*- coding: utf-8 -*-

import binascii
from lib.payload.shellcode.stack import engine as stack
from core.compatible import version

replace_values_static = {
    'xor %ebx,%ebx': '31 db',
    'xor %ecx,%ecx': '31 c9',
    'xor %eax,%ebx': '31 c3',
    'xor %ecx,%ebx': '31 cb',
    'xor %ebx,%eax': '31 d8',
    'xor %eax,%eax': '31 c0',
    'xor %ebx,%edx': '31 da',
    'xor %edx,%edx': '31 d2',
    'mov %esp,%ebx': '89 e3',
    'mov $0x1,%al': 'b0 01',
    'mov $0x01,%al': 'b0 01',
    'mov $0x1,%bl': 'b3 01',
    'mov $0x01,%bl': 'b3 01',
    'mov $0xb,%al': 'b0 0b',
    'mov %eax,%ebx': '89 c3',
    'mov %esp,%ecx': '89 e1',
    'mov %esp,%esi': '89 e6',
    'shr $0x10,%ebx': 'c1 eb 10',
    'shr $0x08,%ebx': 'c1 eb 08',
    'shr $0x8,%ebx': 'c1 eb 08',
    'shr $0x10,%eax': 'c1 e8 10',
    'shr $0x08,%eax': 'c1 e8 08',
    'shr $0x8,%eax': 'c1 e8 08',
    'shr $0x10,%ecx': 'c1 e9 10',
    'shr $0x8,%ecx': 'c1 e9 08',
    'shr $0x08,%ecx': 'c1 e9 08',
    'shr $0x10,%edx': 'c1 ea 10',
    'shr $0x8,%edx': 'c1 ea 08',
    'shr $0x08,%edx': 'c1 ea 08',
    'inc %eax': '40',
    'inc %ebx': '43',
    'inc %ecx': '41',
    'inc %edx': '42',
    'dec %eax': '48',
    'dec %ebx': '4b',
    'dec %ecx': '49',
    'dec %edx': '4a',
    'add %ecx,%ebx': '01 cb',
    'add %eax,%ebx': '01 c3',
    'add %ebx,%edx': '01 da',
    'add %ebx,%eax': '01 d8',
    'push %eax': '50',
    'push %ebx': '53',
    'push %ecx': '51',
    'push %edx': '52',
    'push %esi': '56',
    'push %edi': '57',
    'neg %eax': 'f7 d8',
    'neg %ebx': 'f7 db',
    'neg %ecx': 'f7 d9',
    'neg %edx': 'f7 da',
    'sub %eax,%ebx': '29 c3',
    'sub %ebx,%edx': '29 da',
    'sub %ebx,%eax': '29 d8',
    'sub %ebx,%ecx': '29 d9',
    'sub %ecx,%ebx': '29 cb',
    'pop %eax': '58',
    'pop %ebx': '5b',
    'pop %ecx': '59',
    'pop %edx': '5a',
    'cltd': '99',
    'int $0x80': 'cd 80',
}


def preprocess_shellcode(shellcode):
    shellcode = shellcode.replace('\n\n', '\n').replace('\n\n', '\n').replace(
        '    ', ' ').replace('   ', ' ')
    for data in replace_values_static:
        shellcode = shellcode.replace(data, replace_values_static[data])
    return shellcode


def parse_xor_opcode(line, shellcode):
    if '$0x' in line:
        if '%eax' in line.rsplit(',')[1]:
            if len(line.rsplit(',')[0]) == 8 or len(line.rsplit(',')[
                    0]) == 9:
                rep = str('83 f0') + str(line.rsplit('$0x')[1].rsplit(
                    ',')[0])
                shellcode = shellcode.replace(line, rep)
            if len(line.rsplit(',')[0]) >= 14:
                try:
                    if version() == 2:
                        rep = str('35') + str(stack.st(
                            binascii.a2b_hex(str(line.rsplit('$0x')[
                                1].rsplit(',')[0]))))
                    if version() == 3:
                        rep = str('35') + str(stack.st(
                            (binascii.a2b_hex((line.rsplit('$0x')[
                                1].rsplit(',')[0]).encode('latin-1'))
                             ).decode('latin-1')))
                    shellcode = shellcode.replace(line, rep)
                except:
                    if version() == 2:
                        rep = str('35') + str(stack.st(
                            binascii.a2b_hex(str('0') + str(
                                line.rsplit('$0x')[1].rsplit(',')[
                                    0]))))
                    if version() == 3:
                        rep = str('35') + str(stack.st((
                            binascii.a2b_hex((str('0') + str(
                                line.rsplit('$0x')[1].rsplit(',')[
                                    0])).encode('latin-1'))).decode(
                            'latin-1')))
                shellcode = shellcode.replace(line, rep)
        if '%ebx' in line.rsplit(',')[1]:
            if len(line.rsplit(',')[0]) >= 14:
                try:
                    if version() == 2:
                        rep = str('81 f3') + str(stack.st(
                            binascii.a2b_hex(str(line.rsplit('$0x')[
                                1].rsplit(',')[0]))))
                    if version() == 3:
                        rep = str('81 f3') + str(stack.st(
                            (binascii.a2b_hex((line.rsplit('$0x')[
                                1].rsplit(',')[0]).encode('latin-1'))
                             ).decode('latin-1')))
                    shellcode = shellcode.replace(line, rep)
                except:
                    if version() == 2:
                        rep = str('81 f3') + str(stack.st(
                            binascii.a2b_hex(str('0') + str(
                                line.rsplit('$0x')[1].rsplit(',')[
                                    0]))))
                    if version() == 3:
                        rep = str('81 f3') + str(stack.st((
                            binascii.a2b_hex((str('0') + str(
                                line.rsplit('$0x')[1].rsplit(',')[
                                    0])).encode('latin-1'))).decode(
                            'latin-1')))
                shellcode = shellcode.replace(line, rep)
        if '%ecx' in line.rsplit(',')[1]:
            if len(line.rsplit(',')[0]) >= 14:
                try:
                    if version() == 2:
                        rep = str('81 f1') + str(stack.st(
                            binascii.a2b_hex(str(line.rsplit('$0x')[
                                1].rsplit(',')[0]))))
                    if version() == 3:
                        rep = str('81 f1') + str(stack.st(
                            (binascii.a2b_hex((line.rsplit('$0x')[
                                1].rsplit(',')[0]).encode('latin-1'))
                             ).decode('latin-1')))
                    shellcode = shellcode.replace(line, rep)
                except:
                    if version() == 2:
                        rep = str('81 f1') + str(stack.st(
                            binascii.a2b_hex(str('0') + str(
                                line.rsplit('$0x')[1].rsplit(',')[
                                    0]))))
                    if version() == 3:
                        rep = str('81 f1') + str(stack.st((
                            binascii.a2b_hex((str('0') + str(
                                line.rsplit('$0x')[1].rsplit(',')[
                                    0])).encode('latin-1'))).decode(
                            'latin-1')))
                shellcode = shellcode.replace(line, rep)
        if '%edx' in line.rsplit(',')[1]:
            if len(line.rsplit(',')[0]) >= 14:
                try:
                    if version() == 2:
                        rep = str('81 f2') + str(stack.st(
                            binascii.a2b_hex(str(line.rsplit('$0x')[
                                1].rsplit(',')[0]))))
                    if version() == 3:
                        rep = str('81 f2') + str(stack.st(
                            (binascii.a2b_hex((line.rsplit('$0x')[
                                1].rsplit(',')[0]).encode('latin-1'))
                             ).decode('latin-1')))
                    shellcode = shellcode.replace(line, rep)
                except:
                    if version() == 2:
                        rep = str('81 f2') + str(stack.st(
                            binascii.a2b_hex(str('0') + str(
                                line.rsplit('$0x')[1].rsplit(',')[
                                    0]))))
                    if version() == 3:
                        rep = str('81 f2') + str(stack.st((
                            binascii.a2b_hex((str('0') + str(
                                line.rsplit('$0x')[1].rsplit(',')[
                                    0])).encode('latin-1'))).decode(
                            'latin-1')))
                shellcode = shellcode.replace(line, rep)

    return shellcode


def parse_add_opcode(line, shellcode):
    if '$0x' in line:
        if '%eax' in line.rsplit(',')[1]:
            if len(line.rsplit(',')[0]) == 8 or len(line.rsplit(',')[
                    0]) == 9:
                rep = str('83 c0') + str(line.rsplit('$0x')[1].rsplit(
                    ',')[0])
                shellcode = shellcode.replace(line, rep)
            if len(line.rsplit(',')[0]) >= 14:
                try:
                    if version() == 2:
                        rep = str('05') + str(stack.st(
                            binascii.a2b_hex(str(line.rsplit('$0x')[
                                1].rsplit(',')[0]))))
                    if version() == 3:
                        rep = str('05') + str(stack.st(
                            (binascii.a2b_hex((line.rsplit('$0x')[
                                1].rsplit(',')[0]).encode('latin-1'))
                             ).decode('latin-1')))
                    shellcode = shellcode.replace(line, rep)
                except:
                    if version() == 2:
                        rep = str('05') + str(stack.st(
                            binascii.a2b_hex(str('0') + str(
                                line.rsplit('$0x')[1].rsplit(',')[
                                    0]))))
                    if version() == 3:
                        rep = str('05') + str(stack.st((
                            binascii.a2b_hex((str('0') + str(
                                line.rsplit('$0x')[1].rsplit(',')[
                                    0])).encode('latin-1'))).decode(
                            'latin-1')))
                shellcode = shellcode.replace(line, rep)
        if '%ebx' in line.rsplit(',')[1]:
            if len(line.rsplit(',')[0]) >= 14:
                try:
                    if version() == 2:
                        rep = str('81 c3') + str(stack.st(
                            binascii.a2b_hex(str(line.rsplit('$0x')[
                                1].rsplit(',')[0]))))
                    if version() == 3:
                        rep = str('81 c3') + str(stack.st(
                            (binascii.a2b_hex((line.rsplit('$0x')[
                                1].rsplit(',')[0]).encode('latin-1'))
                             ).decode('latin-1')))
                    shellcode = shellcode.replace(line, rep)
                except:
                    if version() == 2:
                        rep = str('81 c3') + str(stack.st(
                            binascii.a2b_hex(str('0') + str(
                                line.rsplit('$0x')[1].rsplit(',')[
                                    0]))))
                    if version() == 3:
                        rep = str('81 c3') + str(stack.st((
                            binascii.a2b_hex((str('0') + str(
                                line.rsplit('$0x')[1].rsplit(',')[
                                    0])).encode('latin-1'))).decode(
                            'latin-1')))
                shellcode = shellcode.replace(line, rep)
        if '%ecx' in line.rsplit(',')[1]:
            if len(line.rsplit(',')[0]) >= 14:
                try:
                    if version() == 2:
                        rep = str('81 c1') + str(stack.st(
                            binascii.a2b_hex(str(line.rsplit('$0x')[
                                1].rsplit(',')[0]))))
                    if version() == 3:
                        rep = str('81 c1') + str(stack.st(
                            (binascii.a2b_hex((line.rsplit('$0x')[
                                1].rsplit(',')[0]).encode('latin-1'))
                             ).decode('latin-1')))
                    shellcode = shellcode.replace(line, rep)
                except:
                    if version() == 2:
                        rep = str('81 c1') + str(stack.st(
                            binascii.a2b_hex(str('0') + str(
                                line.rsplit('$0x')[1].rsplit(',')[
                                    0]))))
                    if version() == 3:
                        rep = str('81 c1') + str(stack.st((
                            binascii.a2b_hex((str('0') + str(
                                line.rsplit('$0x')[1].rsplit(',')[
                                    0])).encode('latin-1'))).decode(
                            'latin-1')))
                shellcode = shellcode.replace(line, rep)
        if '%edx' in line.rsplit(',')[1]:
            if len(line.rsplit(',')[0]) >= 14:
                try:
                    if version() == 2:
                        rep = str('81 c2') + str(stack.st(
                            binascii.a2b_hex(str(line.rsplit('$0x')[
                                1].rsplit(',')[0]))))
                    if version() == 3:
                        rep = str('81 c2') + str(stack.st(
                            (binascii.a2b_hex((line.rsplit('$0x')[
                                1].rsplit(',')[0]).encode('latin-1'))
                             ).decode('latin-1')))
                    shellcode = shellcode.replace(line, rep)
                except:
                    if version() == 2:
                        rep = str('81 c2') + str(stack.st(
                            binascii.a2b_hex(str('0') + str(
                                line.rsplit('$0x')[1].rsplit(',')[
                                    0]))))
                    if version() == 3:
                        rep = str('81 c2') + str(stack.st((
                            binascii.a2b_hex((str('0') + str(
                                line.rsplit('$0x')[1].rsplit(',')[
                                    0])).encode('latin-1'))).decode(
                            'latin-1')))
                shellcode = shellcode.replace(line, rep)
    return shellcode


def get_registry_opcode_sub(line):
    second_op = line.rsplit(',')[1]
    if len(line.rsplit(',')[0]) >= 14:
        if '%eax' in second_op:
            return '2d'
        elif '%ebx' in second_op:
            return '81 eb'
        elif '%ecx' in second_op:
            return '81 e9'
        elif '%edx' in second_op:
            return '81 ea'
        else:
            return None
    elif len(line.rsplit(',')[0]) in [8, 9] and '%eax' in second_op:
        return '83 e8'


def parse_sub_opcode(line, shellcode):
    """
    >>> parse_sub_opcode('sub $0x1,%eax', 'sub $0x1,%eax')
    '83 e801'
    >>> parse_sub_opcode('sub $0x10000000,%eax', 'sub $0x10000000,%eax')
    '2d00000010'
    >>> parse_sub_opcode('sub $0x1000000,%eax', 'sub $0x1000000,%eax')
    '2d00000001'
    >>> parse_sub_opcode('sub $0x10000000,%ebx', 'sub $0x10000000,%ebx')
    '81 eb00000010'
    >>> parse_sub_opcode('sub $0x1000000,%ebx', 'sub $0x1000000,%ebx')
    '81 eb00000001'
    >>> parse_sub_opcode('sub $0x10000000,%ecx', 'sub $0x10000000,%ecx')
    '81 e900000010'
    >>> parse_sub_opcode('sub $0x1000000,%ecx', 'sub $0x1000000,%ecx')
    '81 e900000001'
    >>> parse_sub_opcode('sub $0x10000000,%edx', 'sub $0x10000000,%edx')
    '81 ea00000010'
    >>> parse_sub_opcode('sub $0x1000000,%edx', 'sub $0x1000000,%edx')
    '81 ea00000001'
    """

    if '$0x' in line:
        first_operand = parse_immediate_hex_value_in_first_op(
            line, pad=True)
        reg_opcode = get_registry_opcode_sub(line)
        if reg_opcode:
            rep = compatible_stacker_with_preppend(reg_opcode, first_operand)
            shellcode = shellcode.replace(line, rep)

    return shellcode


def parse_immediate_hex_value(line):
    """
    >>> parse_immediate_hex_value('$0x10')
    '10'
    >>> parse_immediate_hex_value('$0x123')
    '123'

    What about values more than 0xff ???
    """

    return str(line.rsplit('$0x')[1])


def parse_immediate_hex_value_in_first_op(line, pad=False):
    """
    >>> parse_immediate_hex_value_in_first_op('mov $0x10,%al')
    '10'
    >>> parse_immediate_hex_value_in_first_op('mov $0x1')
    '1'
    >>> parse_immediate_hex_value_in_first_op('mov $0x1', pad=True)
    '01'

    What about values more than 0xff ???
    """

    result = parse_immediate_hex_value(line).rsplit(',')[0]
    if len(result) % 2 and pad:
        return '0' + result
    return result


def get_second_operand(line):
    """
    >>> get_second_operand('mov $0x10,%al')
    '%al'
    >>> get_second_operand('mov %bl,$0x10')
    '$0x10'
    """
    return line.rsplit(',')[1]


def parse_mov_opcode(line):
    """
    >>> parse_mov_opcode('mov $0x10,%al')
    'b010'
    >>> parse_mov_opcode('mov $0x10,%bl')
    'b310'
    """
    rep = None
    if len(line) == 13 or len(line) == 12:
        if '%al' in get_second_operand(line):
            rep = 'b0' + parse_immediate_hex_value_in_first_op(line)
        if '%bl' in get_second_operand(line):
            rep = 'b3' + parse_immediate_hex_value_in_first_op(line)

    return rep


def compatible_stacker(value):
    rep = None
    if version() == 2:
        return stack.st(str(binascii.a2b_hex(value)))
    if version() == 3:
        return stack.st(((binascii.a2b_hex(value.encode('latin-1'))).decode('latin-1')))

    return rep


def compatible_stacker_with_preppend(predefined, value_to_stack):
    return predefined + compatible_stacker(value_to_stack)


def parse_push_opcode(line, shellcode):
    prefix = ''
    if len(line) in [9, 15]:
        prefix = '0'
    if len(line) in [9, 10]:
        rep = str('6a') + prefix + parse_immediate_hex_value(line)
        shellcode = shellcode.replace(line, rep, 1)
    if len(line) in [15, 16]:
        immediate_value = parse_immediate_hex_value(line)
        if len(line) == 15:
            immediate_value = '0' + immediate_value
        rep = str('68') + compatible_stacker(immediate_value)
        shellcode = shellcode.replace(line, rep)

    return shellcode


def process_shellcode_lines(shellcode):
    """
    >>> process_shellcode_lines('mov $0x10,%bl')
    'b310'
    """
    shellcode_lines = shellcode.rsplit('\n')
    for line in shellcode_lines:
        if 'xor' in line:
            shellcode = parse_xor_opcode(line, shellcode)
        if 'add' in line:
            shellcode = parse_add_opcode(line, shellcode)
        if 'sub' in line:
            shellcode = parse_sub_opcode(line, shellcode)
        if 'mov $0x' in line:
            opcode = parse_mov_opcode(line)
            if opcode:
                shellcode = shellcode.replace(line, opcode)
        if 'push $0x' in line:
            shellcode = parse_push_opcode(line, shellcode)

    return shellcode


def convert(shellcode):
    """
    >>> convert('mov $0x10,%bl')
    '\\\\xb3\\\\x10'
    """
    shellcode = preprocess_shellcode(shellcode)
    shellcode = process_shellcode_lines(shellcode)
    shellcode = stack.shellcoder(shellcode.replace('\n', '').replace(' ', ''))
    return shellcode
