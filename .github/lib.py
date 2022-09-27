
import sys
import subprocess

_UNDERLINE = '\033[4m'
_BOLD = '\033[1m'

def _msg(msg, *args, margin=False):
    print('{}{}{}{}'.format(
                '\n' if margin else '',
                ''.join(args), msg, '\033[0m'),
          flush=True)

def _msg_exec(msg):
    _msg('$ {}'.format(msg), '\033[31m')

def header(msg):
    _msg('➤ {}'.format(msg), '\033[35m', _UNDERLINE, _BOLD, margin=True)

def action(msg):
    _msg('✔ {}'.format(msg), '\033[36m', _BOLD, margin=True)

def info(msg):
    _msg('🛈 {}'.format(msg), '\033[33m')

def fail(msg, exit=True, exit_code=1):
    _msg('✗ {}'.format(msg), '\033[30;41m', _BOLD)
    if exit:
        sys.exit(exit_code)

def _sanity_checks(elements, test, display):
    info('sanity checks ({}):'.format(len(elements)))
    sane = True
    for left, right in elements:
        res = test(left, right)
        if not res:
            sane = False
        info('  {} => {}'.format(display(left, right), 'OK' if res else 'FAIL'))
    if not sane:
        fail('sanity checks failed!')

def assert_equality(elements):
    _sanity_checks(elements,
                   lambda a, b: a == b,
                   lambda a, b: '"{}" == "{}"'.format(a, b))

def assert_inequality(elements):
    _sanity_checks(elements,
                   lambda a, b: a != b,
                   lambda a, b: '"{}" != "{}"'.format(a, b))

def assert_in(elements):
    _sanity_checks(elements,
                   lambda a, b: a in b,
                   lambda a, b: '"{}" in "{}"'.format(a, b))

def assert_not_in(elements):
    _sanity_checks(elements,
                   lambda a, b: a not in b,
                   lambda a, b: '"{}" not in "{}"'.format(a, b))

def assert_length(elements):
    _sanity_checks(elements,
                   lambda a, b: len(a) == b,
                   lambda a, b: 'len({}) == {}'.format(a, b))

def assert_length_under(elements):
    _sanity_checks(elements,
                   lambda a, b: len(a) < b,
                   lambda a, b: 'len({}) < {}'.format(a, b))

def assert_length_above(elements):
    _sanity_checks(elements,
                   lambda a, b: len(a) > b,
                   lambda a, b: 'len({}) > {}'.format(a, b))

def run(*args, cwd=None, env=None, shell=False, can_fail=False, capture_output=False, decode_output=True):
    _msg_exec(' '.join("'{}'".format(arg) for arg in args))
    try:
        call = subprocess.run(args, cwd=cwd, env=env, shell=shell, capture_output=capture_output)
        if not can_fail:
            call.check_returncode()
        if capture_output:
            return call.stdout.decode('utf-8') if decode_output else call.stdout
    except subprocess.CalledProcessError as err:
        fail('return code = {}'.format(call.returncode), exit_code=call.returncode)
    except Exception as err:
        fail(err)
